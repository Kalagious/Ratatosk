#pragma once
#include "general.h"
#include <functional>
#include "framemanager.h"
#include "jopmanager.h"
#include "offsets.h"


class ShadowAssassin
{
private:
    std::function<void(UINT64*, UINT64, UINT64)> readFn;
    std::function<void(UINT64, UINT64)>          writeFn;

    UINT64 scratchAddress;
	UINT64 EPROCESS;

    FrameManager frameManager;
    JOPManager   jopManager;


    UINT64 GetCurrentEPROCESS(UINT64 eprocess);
    UINT64 ResolveKernelExport(const std::string& name);

public:
    ShadowAssassin();

    void SetReadPrimitive(std::function<void(UINT64*, UINT64, UINT64)> fn);
    void SetWritePrimitive(std::function<void(UINT64, UINT64)> fn);
    void SetScratchAddress(UINT64 addr);
    void SetEPROCESS(UINT64 ep);

    bool Initialize();

    UINT64 CallSyscall(const std::string& name, const std::vector<UINT64>& params);

    FrameManager& GetFrameManager();
    JOPManager&   GetJOPManager();
};
