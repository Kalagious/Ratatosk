#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <windows.h>
#include <string>
#include <unordered_map>
#include <optional>
#include <algorithm>
#include <cctype>
#include <vector>
#include <cstdio>
#include <cstdarg>
#include <psapi.h>

inline UINT64 TimeUs() {
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    return (cnt.QuadPart * 1000000ULL) / freq.QuadPart;
}

// Format elapsed microseconds as a decimal ms string e.g. "1.234ms"
inline std::string FmtMs(UINT64 us) {
    char buf[32];
    sprintf_s(buf, sizeof(buf), "%llu.%03llums", us / 1000, us % 1000);
    return buf;
}

inline void DbgLog(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);

    // ntdll!DbgPrint routes through NtDebugPrint — visible in kernel debugger output
    using FnDbgPrint = ULONG(NTAPI*)(PCSTR, ...);
    static FnDbgPrint fnDbgPrint = (FnDbgPrint)GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgPrint");

    if (fnDbgPrint) {
        char buf[1024];
        va_start(args, fmt);
        vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
        va_end(args);
        fnDbgPrint("%s", buf);
    }
}

static bool IsValidKernelAddress(UINT64 addr) {
    return addr >= 0xFFFF800000000000ULL && addr <= 0xFFFFFFFFFFFFFFF0ULL;
}
