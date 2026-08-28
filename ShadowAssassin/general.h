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


inline FILE* DbgLogFile() {
    static FILE* f = nullptr;
    if (!f) {
        f = fopen("C:\\ShadowAssassin_debug.log", "a");
        if (f) setvbuf(f, nullptr, _IONBF, 0); // unbuffered — immediate writes
    }
    return f;
}

inline void DbgLog(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);

    FILE* f = DbgLogFile();
    if (f) {
        va_list args2;
        va_start(args2, fmt);
        vfprintf(f, fmt, args2);
        va_end(args2);
        fflush(f);
    }
}