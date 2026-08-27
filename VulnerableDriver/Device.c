/*++
Module Name:
    device.c
--*/

#include "driver.h"
#include "device.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, VulnerableDriverCreateDevice)
#endif

NTSTATUS
VulnerableDriverCreateDevice(
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    PDEVICE_CONTEXT deviceContext;
    WDFDEVICE device;
    NTSTATUS status;
    DECLARE_CONST_UNICODE_STRING(deviceName,  L"\\Device\\VulnDriver");
    DECLARE_CONST_UNICODE_STRING(symbolicLink, L"\\DosDevices\\VulnDriver");

    PAGED_CODE();

    // Name the device so the lib can open \\.\VulnerableDriver
    status = WdfDeviceInitAssignName(DeviceInit, &deviceName);
    if (!NT_SUCCESS(status)) return status;

    // Non-PnP control device — no hardware, created at DriverEntry time
    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetCharacteristics(DeviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) return status;

    deviceContext = DeviceGetContext(device);
    deviceContext->PrivateDeviceData = 0;

    // Symbolic link: \\.\VulnerableDriver
    status = WdfDeviceCreateSymbolicLink(device, &symbolicLink);
    if (!NT_SUCCESS(status)) return status;

    // Also register the device interface GUID for libs that use SetupDi
    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_VulnerableDriver, NULL);
    if (!NT_SUCCESS(status)) return status;

    status = VulnerableDriverQueueInitialize(device);
    if (!NT_SUCCESS(status)) return status;

    // Required for non-PnP control devices — signals WDF the device is ready
    WdfControlFinishInitializing(device);
    return STATUS_SUCCESS;
}
