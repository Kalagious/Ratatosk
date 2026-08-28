#pragma once

// Windows 11 25h2
#define OFF_PID 0x1d0 // EPROCESS->pid
#define OFF_EPROCESS_LIST 0x1d8 // EPROCESS->flink
#define OFF_EPROCESS_THREAD_LIST_HEAD 0x370 // EPROCESS->ThreadListHead
#define OFF_ETHREAD_THREAD_LIST_HEAD 0x578 // ETHREAD->ThreadListHead
#define OFF_CID_UNIQUE_THREAD 0x510 // ETHREAD->Cid.UniqueThread
#define OFF_KTHREAD_LIST_ENTRY 0x2f8 // KTHREAD->ThreadListEntry
#define OFF_KTHREAD_TRAP_FRAME 0x90 // KTHREAD->TrapFrame
#define OFF_KTHREAD_PREVIOUS_MODE 0x232 // KTHREAD->PreviousMode (KPROCESSOR_MODE, 1 byte)
#define OFF_PS_INITIAL_SYSTEM_PROCESS 0xfc6af0 // ADMIN -> EPROCESS
#define KUSERSHAREDDATA_SIZE 0xa80

// ntoskrnl.exe section RVAs — verify with: dumpbin /headers ntoskrnl.exe
// or: !dh nt in WinDbg
#define OFF_NTOSKRNL_DATA 0xE00000  // .data section RVA — verified via !dh nt on Win11 26100
                                    // virtual size 0x1C4330 (~1.8MB), scratch at +0x80000 = 0xE80000