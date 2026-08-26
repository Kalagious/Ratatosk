
uint64_t getKtrapFrameRegisterOffset(std::string regName) {
    // Convert input string to lowercase for case-insensitive lookup
    std::transform(regName.begin(), regName.end(), regName.begin(),
        [](unsigned char c){ return std::tolower(c); });

    static const std::unordered_map<std::string, uint64_t> offsets = {
        // Control / Status Registers
        {"mxcsr", 0x02C},
        {"eflags", 0x178},
        {"rflags", 0x178}, // Alias
        {"rip", 0x168},
        {"rsp", 0x180},
        
        // General Purpose Registers (GPRs)
        {"rax", 0x030},
        {"rcx", 0x038},
        {"rdx", 0x040},
        {"r8",  0x048},
        {"r9",  0x050},
        {"r10", 0x058},
        {"r11", 0x060},
        {"rbx", 0x140},
        {"rdi", 0x148},
        {"rsi", 0x150},
        {"rbp", 0x158},
        
        // Segment Registers
        {"segds", 0x130}, {"ds", 0x130},
        {"seges", 0x132}, {"es", 0x132},
        {"segfs", 0x134}, {"fs", 0x134},
        {"seggs", 0x136}, {"gs", 0x136},
        {"segcs", 0x170}, {"cs", 0x170},
        {"segss", 0x188}, {"ss", 0x188},
        {"gsbase", 0x068},
        {"gsswap", 0x068},
        
        // SIMD / XMM Registers
        {"xmm0", 0x070},
        {"xmm1", 0x080},
        {"xmm2", 0x090},
        {"xmm3", 0x0A0},
        {"xmm4", 0x0B0},
        {"xmm5", 0x0C0},
        
        // Debug Registers
        {"dr0", 0x0D8},
        {"dr1", 0x0E0},
        {"dr2", 0x0E8},
        {"dr3", 0x0F0},
        {"dr6", 0x0F8},
        {"dr7", 0x100},
        {"debugcontrol", 0x108}
    };

    auto it = offsets.find(regName);
    if (it != offsets.end()) {
        return it->second;
    }
    
    // Return the maximum possible uint64_t value to indicate "not found"
    return UINT64_MAX; 
}