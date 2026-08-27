#include "general.h"


class FrameManager
{
    private:
        uint64_t frameAddress;
        uint64_t getKtrapFrameRegisterOffset(std::string regName);


    public:
        void StoreFrame();
        uint64_t ReadStoredRegister();
        void WriteRegister(std::string regName, uint64_t value);
        uint64_t ReadRegister(std::string regName);

        void CreateFrozenThread();

}