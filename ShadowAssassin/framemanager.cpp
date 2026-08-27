#include "framemanager.h"

// Win11 x64 — verify against current dump.cs
static const UINT64 OFF_THREAD_LIST_HEAD   = 0x370; // EPROCESS->ThreadListHead (Win11 26100)
static const UINT64 OFF_KTHREAD_LIST_ENTRY = 0x2f8; // KTHREAD->ThreadListEntry (Win11 26100)
static const UINT64 OFF_CID_UNIQUE_THREAD  = 0x4B8; // ETHREAD->Cid.UniqueThread

static bool IsValidKernelAddress(UINT64 addr) {
    return addr >= 0xFFFF800000000000ULL && addr <= 0xFFFFFFFFFFFFFFF0ULL;
}


FrameManager::FrameManager()
    : threadHandle(nullptr), threadId(0), frameAddress(0), ktrapFrameOffset(0), eprocess(0)
{}

void FrameManager::SetReadPrimitive(std::function<void(UINT64*, UINT64, UINT64)> fn) {
    readFn = fn;
}

void FrameManager::SetWritePrimitive(std::function<void(UINT64, UINT64)> fn) {
    writeFn = fn;
}

void FrameManager::SetTrapFrameOffset(UINT64 offset) {
    ktrapFrameOffset = offset;
}

void FrameManager::SetEPROCESS(UINT64 ep) {
    DbgLog("[FrameManager::SetEPROCESS] eprocess=0x%llX\n", ep);
    eprocess = ep;
}


DWORD WINAPI FrameManager::DummyThreadProc(LPVOID) {
    SuspendThread(GetCurrentThread());
    return 0;
}

UINT64 FrameManager::FindKthread() {
    if (!eprocess) {
        DbgLog("[FindKthread] FAIL: eprocess not set\n");
        return 0;
    }
    if (!readFn) {
        DbgLog("[FindKthread] FAIL: readFn not set\n");
        return 0;
    }

    UINT64 listHead = eprocess + OFF_THREAD_LIST_HEAD;
    if (!IsValidKernelAddress(listHead)) {
        DbgLog("[FindKthread] FAIL: listHead=0x%llX is not a valid kernel address\n", listHead);
        return 0;
    }
    UINT64 flink = 0;
    readFn(&flink, listHead, sizeof(UINT64));

    DbgLog("[FindKthread] EPROCESS=0x%llX ThreadListHead=0x%llX flink=0x%llX tid=%lu\n",
        eprocess, listHead, flink, threadId);

    UINT64 current = flink;
    for (int i = 0; i < 4096; i++) {
        if (!current || current == listHead) {
            DbgLog("[FindKthread] FAIL: walked full list (%d entries), tid=%lu not found\n", i, threadId);
            return 0;
        }

        UINT64 ethread = current - OFF_KTHREAD_LIST_ENTRY;
        if (!IsValidKernelAddress(ethread)) {
            DbgLog("[FindKthread] FAIL: ethread=0x%llX invalid at entry %d\n", ethread, i);
            return 0;
        }

        UINT64 tid = 0;
        readFn(&tid, ethread + OFF_CID_UNIQUE_THREAD, sizeof(UINT64));

        DbgLog("[FindKthread] [%d] ETHREAD=0x%llX TID=%llu\n", i, ethread, tid);

        if ((DWORD)tid == threadId) {
            DbgLog("[FindKthread] Found KTHREAD=0x%llX for tid=%lu\n", ethread, threadId);
            return ethread;
        }

        UINT64 nextFlink = 0;
        readFn(&nextFlink, current, sizeof(UINT64));
        if (!IsValidKernelAddress(nextFlink)) {
            DbgLog("[FindKthread] FAIL: nextFlink=0x%llX invalid at entry %d\n", nextFlink, i);
            return 0;
        }
        current = nextFlink;
    }

    DbgLog("[FindKthread] FAIL: hit 4096 entry limit\n");
    return 0;
}

void FrameManager::CreateFrozenThread() {
    DWORD dwTid = 0;
    threadHandle = CreateThread(nullptr, 0, DummyThreadProc, nullptr, 0, &dwTid);
    if (!threadHandle) {
        DbgLog("[CreateFrozenThread] FAIL: CreateThread failed GLE=%lu\n", GetLastError());
        return;
    }
    threadId = dwTid;
    DbgLog("[CreateFrozenThread] Thread created tid=%lu handle=0x%p, sleeping 50ms\n", dwTid, threadHandle);
    Sleep(50);
    StoreFrame();
}

void FrameManager::StoreFrame() {
    if (!readFn) {
        DbgLog("[StoreFrame] FAIL: readFn not set\n");
        return;
    }

    UINT64 kthread = FindKthread();
    if (!kthread) {
        DbgLog("[StoreFrame] FAIL: FindKthread returned 0\n");
        return;
    }

    frameAddress = 0;
    UINT64 trapFrameAddr = kthread + ktrapFrameOffset;
    if (!IsValidKernelAddress(trapFrameAddr)) {
        DbgLog("[StoreFrame] FAIL: trapFrameAddr=0x%llX invalid\n", trapFrameAddr);
        return;
    }
    readFn(&frameAddress, trapFrameAddr, sizeof(UINT64));
    DbgLog("[StoreFrame] kthread=0x%llX ktrapFrameOffset=0x%llX frameAddress=0x%llX\n",
        kthread, ktrapFrameOffset, frameAddress);

    if (!frameAddress) {
        DbgLog("[StoreFrame] WARN: frameAddress is 0, trap frame may not be set yet\n");
    }

    static const std::vector<std::string> kRegisters = {
        "rax", "rcx", "rdx", "r8",  "r9",  "r10", "r11",
        "rbx", "rdi", "rsi", "rbp", "rsp", "rip",
        "eflags", "mxcsr", "gsbase",
        "segcs", "segss", "segds", "seges", "segfs", "seggs",
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
        "dr0",  "dr1",  "dr2",  "dr3",  "dr6",  "dr7", "debugcontrol"
    };

    storedRegisters.clear();
    for (const auto& reg : kRegisters) {
        UINT64 offset = GetKtrapFrameRegisterOffset(reg);
        UINT64 regAddr = frameAddress + offset;
        if (!IsValidKernelAddress(regAddr)) {
            DbgLog("[StoreFrame] SKIP: %s addr=0x%llX invalid\n", reg.c_str(), regAddr);
            storedRegisters[reg] = 0;
            continue;
        }
        UINT64 val = 0;
        readFn(&val, regAddr, sizeof(UINT64));
        storedRegisters[reg] = val;
        DbgLog("[StoreFrame]   %s @ +0x%llX = 0x%llX\n", reg.c_str(), offset, val);
    }
}

void FrameManager::ContinueThread() {
    if (threadHandle)
        ResumeThread(threadHandle);
}


UINT64 FrameManager::ReadStoredRegister(std::string regName) {
    std::transform(regName.begin(), regName.end(), regName.begin(),
        [](unsigned char c){ return std::tolower(c); });

    auto it = storedRegisters.find(regName);
    if (it == storedRegisters.end()) {
        DbgLog("[ReadStoredRegister] FAIL: '%s' not in stored map\n", regName.c_str());
        return UINT64_MAX;
    }
    return it->second;
}

UINT64 FrameManager::ReadRegister(std::string regName) {
    UINT64 offset = GetKtrapFrameRegisterOffset(regName);
    if (offset == UINT64_MAX) {
        DbgLog("[ReadRegister] FAIL: unknown register '%s'\n", regName.c_str());
        return UINT64_MAX;
    }
    if (!readFn) {
        DbgLog("[ReadRegister] FAIL: readFn not set\n");
        return UINT64_MAX;
    }
    if (!frameAddress) {
        DbgLog("[ReadRegister] FAIL: frameAddress is 0\n");
        return UINT64_MAX;
    }
    UINT64 regAddr = frameAddress + offset;
    if (!IsValidKernelAddress(regAddr)) {
        DbgLog("[ReadRegister] FAIL: addr=0x%llX invalid\n", regAddr);
        return UINT64_MAX;
    }
    UINT64 val = 0;
    readFn(&val, regAddr, sizeof(UINT64));
    DbgLog("[ReadRegister] %s @ frameAddress+0x%llX = 0x%llX\n", regName.c_str(), offset, val);
    return val;
}

void FrameManager::WriteRegister(std::string regName, UINT64 value) {
    UINT64 offset = GetKtrapFrameRegisterOffset(regName);
    if (offset == UINT64_MAX) {
        DbgLog("[WriteRegister] FAIL: unknown register '%s'\n", regName.c_str());
        return;
    }
    if (!writeFn) {
        DbgLog("[WriteRegister] FAIL: writeFn not set\n");
        return;
    }
    if (!frameAddress) {
        DbgLog("[WriteRegister] FAIL: frameAddress is 0\n");
        return;
    }
    DbgLog("[WriteRegister] %s @ frameAddress+0x%llX = 0x%llX\n", regName.c_str(), offset, value);
    UINT64 regAddr = frameAddress + offset;
    if (!IsValidKernelAddress(regAddr)) {
        DbgLog("[WriteRegister] FAIL: addr=0x%llX invalid\n", regAddr);
        return;
    }
    writeFn(regAddr, value);
}

UINT64 FrameManager::GetFrameAddress() const {
    return frameAddress;
}
