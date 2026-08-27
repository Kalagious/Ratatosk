/*++
Module Name:
    driver.c — minimal WDM, no WDF
--*/

#include <ntddk.h>
#include "public.h"

#define IOCTL_GET_FIRST_EPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

static PDEVICE_OBJECT g_DeviceObject = NULL;

DRIVER_UNLOAD DriverUnload;
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\VulnDriver");
    IoDeleteSymbolicLink(&symLink);
    if (g_DeviceObject) IoDeleteDevice(g_DeviceObject);
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Read primitive: user sends [size][kernel_address], driver overwrites with kernel data
NTSTATUS DispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG buffSize = stack->Parameters.Read.Length;

    MDL* mdl = IoAllocateMdl(Irp->UserBuffer, buffSize, FALSE, FALSE, NULL);
    if (!mdl) {
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        Irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_VIOLATION;
    }

    PVOID buf = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (buf) {
        UINT64 readSize    = ((UINT64*)buf)[0];
        UINT64 readAddress = ((UINT64*)buf)[1];
        if (readSize <= buffSize && readAddress) {
            __try {
                RtlCopyMemory(buf, (PVOID)readAddress, readSize);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = buffSize;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Write primitive: user sends [destination_address][data], driver writes to kernel
NTSTATUS DispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG buffSize = stack->Parameters.Write.Length;

    MDL* mdl = IoAllocateMdl(Irp->UserBuffer, buffSize, FALSE, FALSE, NULL);
    if (!mdl) {
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        Irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_VIOLATION;
    }

    PVOID buf = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (buf && buffSize >= sizeof(UINT64) * 2) {
        UINT64 destAddr = ((UINT64*)buf)[0];
        UINT64 data     = ((UINT64*)buf)[1];
        if (destAddr) {
            __try {
                *(UINT64*)destAddr = data;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }

    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = buffSize;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_GET_FIRST_EPROCESS:
        if (stack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(UINT64)) {
            *(UINT64*)Irp->AssociatedIrp.SystemBuffer = (UINT64)PsInitialSystemProcess;
            info = sizeof(UINT64);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\VulnDriver");
    UNICODE_STRING symLink    = RTL_CONSTANT_STRING(L"\\DosDevices\\VulnDriver");

    status = IoCreateDevice(DriverObject, 0, &deviceName,
                            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Neither-IO: driver manages buffer access directly via MDL
    g_DeviceObject->Flags &= ~(DO_BUFFERED_IO | DO_DIRECT_IO);
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DriverObject->DriverUnload                          = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ]           = DispatchRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE]          = DispatchWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, " [VulnDriver] Ready\n");
    return STATUS_SUCCESS;
}
