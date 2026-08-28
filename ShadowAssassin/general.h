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




inline void DbgLog(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
}


static bool IsValidKernelAddress(UINT64 addr) {
    return addr >= 0xFFFF800000000000ULL && addr <= 0xFFFFFFFFFFFFFFF0ULL;
}