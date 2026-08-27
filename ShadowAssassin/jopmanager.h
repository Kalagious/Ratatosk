#pragma once
#include "general.h"


class JOPManager
{
    private:
        UINT64 ntsokrnl;
        UINT64* gadgetChain;
        void resolveChain();
        std::vector<std::string> textGadgetChain;


    public:
        JOPManager();
        ~JOPManager();

        void pushGadget(std::string gadget);
        void printChain();
        void writeChain();

        void SetKernelAddress(UINT64 address);

};
