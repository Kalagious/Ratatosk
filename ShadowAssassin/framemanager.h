#pragma once
#include "general.h"
#include <functional>


class FrameManager
{
private:
    HANDLE      threadHandle;
    DWORD       threadId;
    uint64_t    frameAddress;
    uint64_t    ktrapFrameOffset;
    std::unordered_map<std::string, uint64_t> storedRegisters;

    std::function<uint64_t(uint64_t)>       readFn;
    std::function<void(uint64_t, uint64_t)> writeFn;

    static DWORD WINAPI DummyThreadProc(LPVOID param);
    uint64_t FindKthread();
    uint64_t GetKtrapFrameRegisterOffset(std::string regName);

public:
    FrameManager();

    void SetReadPrimitive(std::function<uint64_t(uint64_t)> fn);
    void SetWritePrimitive(std::function<void(uint64_t, uint64_t)> fn);
    void SetTrapFrameOffset(uint64_t offset);

    void CreateFrozenThread();
    void StoreFrame();
    void ContinueThread();

    uint64_t ReadStoredRegister(std::string regName);
    uint64_t ReadRegister(std::string regName);
    void     WriteRegister(std::string regName, uint64_t value);
    uint64_t GetFrameAddress() const;
};
