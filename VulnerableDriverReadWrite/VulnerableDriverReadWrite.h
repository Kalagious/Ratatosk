#pragma once

#include "general.h"

#define IOCTL_GET_FIRST_EPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)


class VulnerableDriver {
public:
	bool primitivesEnabled;

	UINT64 exploitEPROCESS;

	UINT64 reusableIORingCorruptionAddr;
	UINT64 reusableIORingOriginalValue;

	HANDLE hDevice;






	void EnablePrimitives();
	void CleanUp();

	void Read(UINT64* iDestinationAddr, UINT64 iTargetAddr, UINT64 iSize);
	void Write(UINT64 iDestinationAddr, UINT64 data);

	UINT64 GetEPROCESS();
};