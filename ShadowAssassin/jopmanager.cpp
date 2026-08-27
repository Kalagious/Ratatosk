#include "jopmanager.h"
#include <cstdio>


JOPManager::JOPManager() : ntsokrnl(0), gadgetChain(nullptr) {}

JOPManager::~JOPManager() {
    delete[] gadgetChain;
}

void JOPManager::SetKernelAddress(UINT64 address) {
    DbgLog("[JOPManager::SetKernelAddress] ntsokrnl=0x%llX\n", address);
    ntsokrnl = address;
}

void JOPManager::pushGadget(std::string gadget) {
    DbgLog("[JOPManager::pushGadget] [%zu] %s\n", textGadgetChain.size(), gadget.c_str());
    textGadgetChain.push_back(gadget);
}

void JOPManager::printChain() {
    DbgLog("[JOPManager::printChain] %zu gadgets:\n", textGadgetChain.size());
    for (size_t i = 0; i < textGadgetChain.size(); i++) {
        DbgLog("  [%zu] %s\n", i, textGadgetChain[i].c_str());
        printf("[%zu] %s\n", i, textGadgetChain[i].c_str());
    }
}

void JOPManager::resolveChain() {
    if (textGadgetChain.empty()) {
        DbgLog("[JOPManager::resolveChain] WARN: chain is empty\n");
    }
    DbgLog("[JOPManager::resolveChain] Resolving %zu gadgets\n", textGadgetChain.size());
    delete[] gadgetChain;
    gadgetChain = new UINT64[textGadgetChain.size()]();
}

void JOPManager::writeChain() {
    DbgLog("[JOPManager::writeChain] Writing chain (%zu gadgets)\n", textGadgetChain.size());
    resolveChain();
}
