#include "framemanager.h"

// Undocumented handle table structs for SystemHandleInformation (class 16).
struct SystemHandleEntry {
    USHORT ProcessId;
    USHORT CreatorBackTrace;
    UCHAR  ObjectType;
    UCHAR  Flags;
    USHORT Handle;
    PVOID  Object;
    ULONG  GrantedAccess;
};

struct SystemHandleTable {
    ULONG             Count;
    SystemHandleEntry Entries[1];
};

// --- Setup ---

FrameManager::FrameManager()
    : threadHandle(nullptr), threadId(0), frameAddress(0), ktrapFrameOffset(0)
{}

void FrameManager::SetReadPrimitive(std::function<uint64_t(uint64_t)> fn) {
    readFn = fn;
}

void FrameManager::SetWritePrimitive(std::function<void(uint64_t, uint64_t)> fn) {
    writeFn = fn;
}

void FrameManager::SetTrapFrameOffset(uint64_t offset) {
    ktrapFrameOffset = offset;
}


// --- Thread lifetime ---

DWORD WINAPI FrameManager::DummyThreadProc(LPVOID) {
    SuspendThread(GetCurrentThread());
    return 0;
}

uint64_t FrameManager::FindKthread() {
    using tNtQuery = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    static auto NtQuery = (tNtQuery)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuery) return 0;

    ULONG size = 0;
    NtQuery(16, nullptr, 0, &size);

    std::vector<uint8_t> buf(size + 0x1000);
    NtQuery(16, buf.data(), (ULONG)buf.size(), &size);

    auto*  table = reinterpret_cast<SystemHandleTable*>(buf.data());
    USHORT pid   = (USHORT)GetCurrentProcessId();
    USHORT hval  = (USHORT)(uintptr_t)threadHandle;

    for (ULONG i = 0; i < table->Count; i++) {
        auto& e = table->Entries[i];
        if (e.ProcessId == pid && e.Handle == hval)
            return (uint64_t)e.Object;
    }
    return 0;
}

void FrameManager::CreateFrozenThread() {
    DWORD dwTid = 0;
    threadHandle = CreateThread(nullptr, 0, DummyThreadProc, nullptr, 0, &dwTid);
    if (!threadHandle) return;

    threadId = dwTid;
    Sleep(50); // let the thread enter the suspend syscall and get a KTRAP_FRAME
    StoreFrame();
}

void FrameManager::StoreFrame() {
    if (!readFn) return;

    uint64_t kthread = FindKthread();
    if (!kthread) return;
    frameAddress = readFn(kthread + ktrapFrameOffset);

    static const std::vector<std::string> kRegisters = {
        "rax", "rcx", "rdx", "r8",  "r9",  "r10", "r11",
        "rbx", "rdi", "rsi", "rbp", "rsp", "rip",
        "eflags", "mxcsr", "gsbase",
        "segcs", "segss", "segds", "seges", "segfs", "seggs",
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
        "dr0",  "dr1",  "dr2",  "dr3",  "dr6",  "dr7", "debugcontrol"
    };

    storedRegisters.clear();
    for (const auto& reg : kRegisters)
        storedRegisters[reg] = readFn(frameAddress + GetKtrapFrameRegisterOffset(reg));
}

void FrameManager::ContinueThread() {
    if (threadHandle)
        ResumeThread(threadHandle);
}


uint64_t FrameManager::ReadStoredRegister(std::string regName) {
    std::transform(regName.begin(), regName.end(), regName.begin(),
        [](unsigned char c){ return std::tolower(c); });

    auto it = storedRegisters.find(regName);
    if (it == storedRegisters.end()) return UINT64_MAX;
    return it->second;
}

uint64_t FrameManager::ReadRegister(std::string regName) {
    uint64_t offset = GetKtrapFrameRegisterOffset(regName);
    if (offset == UINT64_MAX || !readFn || !frameAddress) return UINT64_MAX;
    return readFn(frameAddress + offset);
}

void FrameManager::WriteRegister(std::string regName, uint64_t value) {
    uint64_t offset = GetKtrapFrameRegisterOffset(regName);
    if (offset == UINT64_MAX || !writeFn || !frameAddress) return;
    writeFn(frameAddress + offset, value);
}

uint64_t FrameManager::GetFrameAddress() const {
    return frameAddress;
}
