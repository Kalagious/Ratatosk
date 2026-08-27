#pragma once
#include "general.h"


class JOPManager
{
    private:
        uint64_t ntsokrnl;
        uint64_t* gadgetChain;
        void resolveChain();
        std::vector<std::string> textGadgetChain;


    public:
        JOPManager();
        ~JOPManager();

        void pushGadget(std::string gadget);
        void printChain();
        void writeChain();

        void SetKernelAddress(uint64_t address);

};
