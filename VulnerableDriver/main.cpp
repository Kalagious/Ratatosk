#include "general.h"

extern "C" {
    VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
        UNREFERENCED_PARAMETER(DriverObject);
    }

    NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
        UNREFERENCED_PARAMETER(RegistryPath);
        UNREFERENCED_PARAMETER(DriverObject);
        return STATUS_SUCCESS;
    }
}
