#include "general.h"

NTSTATUS IrpWriteHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG buffSize = stack->Parameters.Write.Length;

    MDL* mdl = IoAllocateMdl(Irp->UserBuffer, buffSize, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    PVOID userInput = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);

    if (!userInput) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " [IrpWrite] Input mapping failed\n");
        return STATUS_FAIL_CHECK;
    }

    switch (stack->MajorFunction) {
    case IRP_MJ_WRITE: {
        // Layout: [size(8)][destAddr][data]
        UINT64 destAddr = ((UINT64*)userInput)[1];
        UINT64 data     = ((UINT64*)userInput)[2];

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            " [IrpWrite] dest=0x%llX data=0x%llX\n", destAddr, data);

        *(UINT64*)destAddr = data;
        break;
    }
    }

    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return STATUS_SUCCESS;
}