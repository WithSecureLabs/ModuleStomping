#pragma once

#define DOS_DEVICE_NAME L"\\DosDevices\\cowspot"
#define DEVICE_NAME		L"\\Device\\cowspot"

struct getPageInfoResponse
{
	unsigned char isValid;
	unsigned char isDirty;
}; typedef struct getPageInfoResponse getPageInfoResponse;

struct getPageInfoRequest
{
	unsigned long targetPID;
	unsigned long numberOfPagesToCheck;
	unsigned long long pageToCheck;
}; typedef struct getPageInfoRequest getPageInfoRequest;

#define IOCTL_DRIVER_QUERY_VA			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

struct setPFNDatabaseRequest
{
	unsigned long long offsetToMmPfnDatabaseInNtDllFromExAllocatePoolWithTag;
}; typedef struct setPFNDatabaseRequest setPFNDatabaseRequest;

#define IOCTL_DRIVER_SET_PFN_DATABASE	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

