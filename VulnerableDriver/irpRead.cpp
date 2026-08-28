#include "general.h"

NTSTATUS IrpReadHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG buffSize = stack->Parameters.Read.Length;

    MDL* mdl = IoAllocateMdl(Irp->UserBuffer, buffSize, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
    PVOID userInput = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);

    if (!userInput) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " [IrpRead] Input mapping failed\n");
        return STATUS_FAIL_CHECK;
    }

    switch (stack->MajorFunction) {
    case IRP_MJ_READ: {
        UINT64 readBufferSize = ((UINT64*)userInput)[0];
        UINT64 readAddress    = ((UINT64*)userInput)[1];

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            " [IrpRead] addr=0x%llX size=%llu\n", readAddress, readBufferSize);

        memcpy(userInput, (void*)readAddress, readBufferSize);
        break;
    }
    }

    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}