#include <Ntifs.h>
#include <Ntddk.h>
//#include <aux_klib.h>
#include "driver.h"
#include "public.h"

_Use_decl_annotations_ DRIVER_INITIALIZE	DriverEntry;
_Use_decl_annotations_ DRIVER_UNLOAD		DriverUnload;
_Dispatch_type_(IRP_MJ_CREATE)			DRIVER_DISPATCH irp_mj_create;
_Dispatch_type_(IRP_MJ_CLOSE)			DRIVER_DISPATCH irp_mj_close;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)	DRIVER_DISPATCH irp_mj_device_control;

NTSTATUS queryVA(getPageInfoRequest* params, getPageInfoResponse* response);
NTSTATUS queryVAFromIRP(PIRP Irp);
NTSTATUS setPFNDatabase(setPFNDatabaseRequest* req);
NTSTATUS setPFNDatabaseFromIRP(PIRP Irp);
int isTableEntryValid(unsigned long long entry);
unsigned long long getChildTableFromTableEntry(unsigned long long entry);
__drv_requiresIRQL(APC_LEVEL) NTSTATUS readMemoryFromPhysical(unsigned long long address, char* errMsg, void* tableOut);

privateInfo prv; 

// TODO: Get PFN structure info via PDBs instead of hardcoding it here.
struct PFN
{
	// 0x00
	unsigned long long padding1;
	// 0x08
	unsigned long long PTEAddress;
	// 0x10
	unsigned long long OriginalPte;
	// 0x18
	unsigned long long u2;
	// 0x20 - u3
	unsigned short referenceCount;
	unsigned char  e1;
	unsigned char  e3;
	unsigned long  e4;	// or e2
	// 0x28
	unsigned long long u4;
};

_Use_decl_annotations_ NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT *DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS s;
	UNICODE_STRING deviceName;
	UNICODE_STRING DOSDeviceName;

	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = irp_mj_create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = irp_mj_close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = irp_mj_device_control;

	// Initialise our 'private' data, shared throughout the driver
	memset(&prv, 0, sizeof(privateInfo));

	// Create our device and the DOS symlink to it, as usual
	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	s = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &prv.deviceObject);
	if (!NT_SUCCESS(s))
	{
		DbgPrint("Failed IoCreateDevice: 0x%08lx\n", s);
		return s;
	}
	RtlInitUnicodeString(&DOSDeviceName, DOS_DEVICE_NAME);

	s = IoCreateSymbolicLink(&DOSDeviceName, &deviceName);
	if (!NT_SUCCESS(s))
	{
		IoDeleteDevice(prv.deviceObject);
		DbgPrint("Failed IoCreateSymbolicLink: 0x%08lx\n", s);
		return s;
	}

	return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ struct _DRIVER_OBJECT *DriverObject)
{
	UNICODE_STRING DOSDeviceName;

	UNREFERENCED_PARAMETER(DriverObject);

	RtlInitUnicodeString(&DOSDeviceName, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&DOSDeviceName);
	IoDeleteDevice(prv.deviceObject);
}

_Use_decl_annotations_ NTSTATUS irp_mj_create(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

_Use_decl_annotations_ NTSTATUS irp_mj_close(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	// FIXME: Make sure all pending requests on this handle are complete
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS setPFNDatabaseFromIRP(PIRP Irp)
{
	PIO_STACK_LOCATION irpStack;
	setPFNDatabaseRequest inputBuffer;
	int bytesReturned;
	NTSTATUS s;

	bytesReturned = 0;

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	if (irpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(setPFNDatabaseRequest))
	{
		s = STATUS_BUFFER_TOO_SMALL;
		goto out;
	}

	memcpy(&inputBuffer, Irp->AssociatedIrp.SystemBuffer, sizeof(setPFNDatabaseRequest));

	s = setPFNDatabase(&inputBuffer);

out:
	Irp->IoStatus.Status = s;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return s;
}

_Use_decl_annotations_ NTSTATUS irp_mj_device_control(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpStack;
	unsigned long functionCode;

	UNREFERENCED_PARAMETER(DeviceObject);

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	functionCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

	switch (functionCode)
	{
	case IOCTL_DRIVER_QUERY_VA:
		return queryVAFromIRP(Irp);
	case IOCTL_DRIVER_SET_PFN_DATABASE:
		return setPFNDatabaseFromIRP(Irp);
	default:
		DbgPrint("IRP_MJ_DEVICE_CONTROL: Unrecognised function code 0x%08lx\n", functionCode);
	}

	Irp->IoStatus.Status = STATUS_ILLEGAL_FUNCTION;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS setPFNDatabase(setPFNDatabaseRequest* req)
{
	PVOID MmPfnDatabaseUnsafe;
	unsigned long long MmPfnDatabase;
	MM_COPY_ADDRESS src;
	SIZE_T bytesRead;
	NTSTATUS s;
	int didExcept;

	unsigned long numberOfPFNs = 0x2000;	// FIXME

	// Since we don't know the base address of ntdll (and don't want to call any undocumented stuff to get it), we accept an offset to MmPfnDatabase
	// from an exported entry (ExAllocatePoolWithTag). Since this comes from userspace, we still need to santise it as best we can. We can't make it
	// foolproof but we can do some basic checks. Since we only ever read the PFN database via MmCopyMemory, it should be safe for userspace to give
	// us a bad address, anyway.
	MmPfnDatabaseUnsafe = (PVOID)( ((unsigned long long)ExAllocatePoolWithTag) - req->offsetToMmPfnDatabaseInNtDllFromExAllocatePoolWithTag );

	// We now have a pointer to MmPfnDatabase, which is itself a pointer to the first PFN. We should try to read it, and find the PFN DB base.
	src.VirtualAddress = MmPfnDatabaseUnsafe;
#pragma warning( push )
#pragma warning( disable : 6001 )	// VS things 'MmPfnDatabase' can be uninitialized in this call. It cannot.
	s = MmCopyMemory(&MmPfnDatabase, src, sizeof(PVOID), MM_COPY_MEMORY_VIRTUAL, &bytesRead);
#pragma warning( pop )
	if (!NT_SUCCESS(s))
	{
		DbgPrint("Cannot read MmPfnDatabase pointer %p as provided by userspace\n", MmPfnDatabaseUnsafe);
		return s;
	}
	if (bytesRead != sizeof(PVOID))
	{
		DbgPrint("Short read of read MmPfnDatabase pointer %p as provided by userspace (read %llu of %llu bytes)\n", MmPfnDatabaseUnsafe, bytesRead, sizeof(PVOID));
		return STATUS_ACCESS_VIOLATION;
	}

	// Now we have the PFN database pointer, and we can do some basic checks on it.
	// It should be aligned on a 4K boundary (I think?). This is totally from observation
	// and may be incorrect.
	if ((MmPfnDatabase & 0x0000000000000fff) != 0)
	{
		DbgPrint("Dereferenced MmPfnDatabase pointer is not correctly aligned?\n");
		return STATUS_BAD_DATA;
	}

	// This should not be in a user-space buffer
	__try
	{
		ProbeForRead((PVOID)MmPfnDatabase, sizeof(struct PFN) * numberOfPFNs, 1);
		didExcept = FALSE;
	}
#pragma warning( push )
#pragma warning( disable : 6320 )	// "warning C6320: Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER. This might mask exceptions that were not intended to be handled."
	__except (EXCEPTION_EXECUTE_HANDLER)
#pragma warning( pop )
	{
		didExcept = TRUE;
	}
	if (!didExcept)
	{
		DbgPrint("Dereferenced MmPfnDatabase pointer is in userspace\n");
		return STATUS_BAD_DATA;
	}

	// TODO: more checks. We're giving userspace the ability to give kernel space a pointer here
	// so we should be as careful as we possibly can be.

	// OK, all our checks passed!
	prv.PFNDatabase = MmPfnDatabase;
	DbgPrint("MmPfnDatabase is 0x%016llx\n", prv.PFNDatabase);
	return STATUS_SUCCESS;
}

NTSTATUS queryVAFromIRP(PIRP Irp)
{
	PIO_STACK_LOCATION irpStack;
	getPageInfoRequest inputBuffer;
	getPageInfoResponse* outputBuffer;
	int bytesReturned;
	NTSTATUS s;

	bytesReturned = 0;

	irpStack = IoGetCurrentIrpStackLocation(Irp);
	if (irpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(getPageInfoRequest))
	{
		s = STATUS_BUFFER_TOO_SMALL;
		goto out;
	}
	memcpy(&inputBuffer, Irp->AssociatedIrp.SystemBuffer, sizeof(getPageInfoRequest));
	if (irpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(getPageInfoResponse) * inputBuffer.numberOfPagesToCheck)
	{
		s = STATUS_BUFFER_TOO_SMALL;
		goto out;
	}

	outputBuffer = (getPageInfoResponse*)Irp->AssociatedIrp.SystemBuffer;
	memset(outputBuffer, 0, sizeof(getPageInfoResponse) * inputBuffer.numberOfPagesToCheck);

	s = queryVA(&inputBuffer, outputBuffer);

	if (NT_SUCCESS(s))
		bytesReturned = sizeof(getPageInfoResponse) * inputBuffer.numberOfPagesToCheck;

out:
	Irp->IoStatus.Status = s;
	Irp->IoStatus.Information = bytesReturned;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return s;
}

NTSTATUS queryVA(getPageInfoRequest* params, getPageInfoResponse* response)
{
	PMDL mdl;
	PPFN_NUMBER pfnArray;
	unsigned int pfnArrayCount;
	unsigned int pfnIdx;
	struct PFN* MmPfnDatabase = (struct PFN*)prv.PFNDatabase;
	struct PFN ourPFN;
	unsigned long long pte;
	KAPC_STATE state;
	PEPROCESS eprocess;
	NTSTATUS s;
	MM_COPY_ADDRESS srcAddress;
	PHYSICAL_ADDRESS phys;
	SIZE_T numRead;

	UNREFERENCED_PARAMETER(response);

	if (params->numberOfPagesToCheck == 0)
	{
		DbgPrint("Asked to scan 0 pages\n");
		return STATUS_INVALID_PARAMETER;
	}

	mdl = IoAllocateMdl((PVOID)params->pageToCheck, 0x1000 * params->numberOfPagesToCheck, FALSE, FALSE, NULL);
	if (!mdl)
	{
		return STATUS_NO_MEMORY;
	}

	s = PsLookupProcessByProcessId((HANDLE)params->targetPID, &eprocess);
	if (!NT_SUCCESS(s))
	{
		IoFreeMdl(mdl);
		DbgPrint("PsLookupProcesByProcessId failed for PID 0x%04lx: 0x%08lx\n", params->targetPID, s);
		return s;
	}

	KeStackAttachProcess(eprocess, &state);

	__try 
	{
		MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
	}
#pragma warning( push )
#pragma warning( disable : 6320 )	// "warning C6320: Exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER. This might mask exceptions that were not intended to be handled."
	__except (EXCEPTION_EXECUTE_HANDLER)
#pragma warning( pop )
	{
		s = STATUS_BAD_DATA;
		goto out;
	}
	pfnArray = MmGetMdlPfnArray(mdl);
	pfnArrayCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));
	// Read the PTE from the PFN database using MmCopyMemory, in case we have the pfn database base address wrong.
	// MmCopyMemory won't let me read us the memory by VA - not 100% sure why but I suspect because it is checked
	// against the PFN table and no mapping is found (?) - so we just translate to physical address and read that
	// instead.
	for (pfnIdx = 0; pfnIdx < pfnArrayCount; pfnIdx++)
	{
		phys = MmGetPhysicalAddress(&MmPfnDatabase[pfnArray[pfnIdx]]);
		srcAddress.PhysicalAddress.QuadPart = phys.QuadPart;
#pragma warning( push )
#pragma warning( disable : 6001 )	// VS things 'ourPFN' can be uninitialized in this call. It cannot.
		s = MmCopyMemory(&ourPFN, srcAddress, sizeof(struct PFN), MM_COPY_MEMORY_PHYSICAL, &numRead);
#pragma warning( pop )
		if (!NT_SUCCESS(s) || numRead != sizeof(struct PFN))
		{
			DbgPrint("Failed to read PFN from PFN database at %p (%p[0x%16llx]): NTSTATUS 0x%08lx, transferred %llu of %llu bytes\n", srcAddress.VirtualAddress, MmPfnDatabase, pfnArray[pfnIdx], s, numRead, sizeof(struct PFN));
			if (NT_SUCCESS(s))
				s = STATUS_PARTIAL_COPY;
			goto out;
		}
		pte = ourPFN.PTEAddress;

		// DbgPrint("VA 0x%016llx PFN %p\n", params->pageToCheck, &MmPfnDatabase[pfn[0]]);

		response[pfnIdx].isValid = TRUE; // TODO
		response[pfnIdx].isDirty = (ourPFN.e1 >> 4) & 0x01;
	}
	s = STATUS_SUCCESS;

out:
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	KeUnstackDetachProcess(&state);

	return s;
}

__drv_requiresIRQL(APC_LEVEL)
NTSTATUS readMemoryFromPhysical(unsigned long long address, char* errMsg, void* tableOut)
{
	NTSTATUS s;
	MM_COPY_ADDRESS srcAddress;
	SIZE_T numRead;
	SIZE_T bytesToRead = 0x200 * sizeof(unsigned long long);

	srcAddress.PhysicalAddress.QuadPart = address;
	s = MmCopyMemory(tableOut, srcAddress, bytesToRead, MM_COPY_MEMORY_PHYSICAL, &numRead);

	if (!NT_SUCCESS(s) || numRead != bytesToRead)
	{
		DbgPrint("Failed to MmCopyMemory table '%s' from physical location 0x%08llx: 0x%08lx (read 0x%08llx of 0x%08llx bytes)\n", errMsg, srcAddress.PhysicalAddress.QuadPart, s, numRead, bytesToRead);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

unsigned long long getChildTableFromTableEntry(unsigned long long entry)
{
	// TODO/FIXME: We should honour the size of the child table pointer here, which is set as
	// M-12 (M being set in the sillicon I think). Bit 63 is XD, and 62-52 is ignored, but 51
	// through M is reserved by the sillicon so we should ignore it..
	return ((unsigned long long)((entry &  ~(0xfff0'0000'0000'0FFF)) ));	
}

int isTableEntryValid(unsigned long long entry)
{
	return (entry & 0x01) != 0;
}