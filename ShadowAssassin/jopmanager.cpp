#include "jopmanager.h"
#include <cstdio>


JOPManager::JOPManager() : ntsokrnl(0), gadgetChain(nullptr) {}

JOPManager::~JOPManager() {
    delete[] gadgetChain;
}

void JOPManager::SetKernelAddress(uint64_t address) {
    ntsokrnl = address;
}

void JOPManager::pushGadget(std::string gadget) {
    textGadgetChain.push_back(gadget);
}

void JOPManager::printChain() {
    for (size_t i = 0; i < textGadgetChain.size(); i++)
        printf("[%zu] %s\n", i, textGadgetChain[i].c_str());
}

void JOPManager::resolveChain() {
    delete[] gadgetChain;
    gadgetChain = new uint64_t[textGadgetChain.size()]();
}

void JOPManager::writeChain() {
    resolveChain();
}
