#include "general.h"

VOID UnloadDriver(PDRIVER_OBJECT DriverObject);
//extern PDRIVER_OBJECT globaldp;
//extern bool runny;

NTSTATUS IrpWriteHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);


    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);



    switch (stack->MajorFunction) {
    case IRP_MJ_WRITE:
        
        break;
    }

    

    return STATUS_SUCCESS;
}