#pragma once
#include "general.h"
#include "ReadWriteLibrary/VulnerableDriverReadWrite.h"
#include <functional>


class FrameManager
{
private:
    HANDLE      threadHandle;
    DWORD       threadId;
    UINT64      frameAddress;
    UINT64      ktrapFrameOffset;
    UINT64      eprocess;
    std::unordered_map<std::string, UINT64> storedRegisters;

    std::function<void(UINT64*, UINT64, UINT64)> readFn;
    std::function<void(UINT64, UINT64)>          writeFn;

    static DWORD WINAPI DummyThreadProc(LPVOID param);
    UINT64 FindKthread();
    UINT64 GetKtrapFrameRegisterOffset(std::string regName);

public:
    FrameManager();

    void SetReadPrimitive(std::function<void(UINT64*, UINT64, UINT64)> fn);
    void SetWritePrimitive(std::function<void(UINT64, UINT64)> fn);
    void SetTrapFrameOffset(UINT64 offset);
    void SetEPROCESS(UINT64 ep);

    void CreateFrozenThread();
    void StoreFrame();
    void ContinueThread();

    UINT64 ReadStoredRegister(std::string regName);
    UINT64 ReadRegister(std::string regName);
    void   WriteRegister(std::string regName, UINT64 value);
    UINT64 GetFrameAddress() const;
};
