#include "stdafx.h"
#include <stdio.h>

#include <stdexcept>
#include <sstream>

#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <string.h>

#include "moduleManipulation.h"

BOOL EnableDebugPrivilege(BOOL bEnable)
{
	HANDLE hToken = nullptr;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;

	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return FALSE;

	return TRUE;
}

unsigned char* getModuleBase(HANDLE toScanHandle, const wchar_t* moduleNameSubstring)
{
	DWORD cbNeeded;
	int s = EnumProcessModules(toScanHandle, NULL, 0, &cbNeeded);
	if (s == 0)
	{
		printf("Couldn't call EnumProcessModules to get buffer size, gle %d\n", GetLastError());
		return NULL;
	}

	HMODULE* moduleList = (HMODULE*)malloc(cbNeeded);
	memset(moduleList, 0, cbNeeded);
	s = EnumProcessModules(toScanHandle, moduleList, cbNeeded, &cbNeeded);
	if (s == 0)
	{
		// This'll happen sometimes if there's a module loaded between our calls. 
		// TODO: we can retry in this case.
		printf("Couldn't call EnumProcessModules to get modules, gle %d.\n", GetLastError());
		return NULL;
	}

	for (HMODULE* thisModPtr = &moduleList[0]; thisModPtr < &moduleList[cbNeeded / sizeof(HMODULE)]; thisModPtr++)
	{
		HMODULE thisModule = *thisModPtr;
		wchar_t szModName[MAX_PATH];
		memset(szModName, 0, MAX_PATH);
		if (GetModuleFileNameEx(toScanHandle, thisModule, szModName, MAX_PATH - sizeof(wchar_t)) == 0)
		{
			printf("GetModuleFileNameEx failed, GLE %d\n", GetLastError());
			continue;
		}
		if (StrStrI(szModName, moduleNameSubstring) != NULL)
		{
			free(moduleList);
			return (unsigned char*)thisModule;
		}
	}
	free(moduleList);
	return NULL;
}

BOOL isModuleLoaded(HANDLE toScanHandle, const wchar_t* moduleNameSubstring)
{
	return getModuleBase(toScanHandle, moduleNameSubstring) != NULL;
}

void* injectLoadLibrary(HANDLE toScanHandle, const wchar_t* toLoad)
{
	// Find kernelbase and then LoadLibraryA
	moduleInMemory kernelbase(toScanHandle, L"kernelbase.dll");
	unsigned long long loadLibraryWInTargetProcess = kernelbase.resolveExport(L"LoadLibraryW");

	// Put the name of the module we're loading in the target's address space
	unsigned long long moduleName = (unsigned long long)VirtualAllocEx(toScanHandle, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (moduleName == NULL)
	{
		std::wstringstream os(L"");
		os << "Failed to allocate 0x1000 bytes for module name: GetLastError is " << std::dec << GetLastError();
		throw errorMaker::wruntime_error(&os);
	}
	SIZE_T written = 0;
	SIZE_T toWrite = lstrlenW(toLoad) * sizeof(wchar_t);
	if (!WriteProcessMemory(toScanHandle, (void*)moduleName, toLoad, toWrite, &written) || written != toWrite)
	{
		std::wstringstream os(L"");
		os << "Failed to copy module name to target process; GetLastError is " << GetLastError();
		throw errorMaker::wruntime_error(&os);
	}

	// And create the thread that will do the load.
	DWORD tid;
	HANDLE s = CreateRemoteThread(toScanHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryWInTargetProcess, (char*)moduleName, 0, &tid);
	if (!s)
	{
		std::wstringstream os(L"");
		os << "CreateRemoteThread failed, GLE %d" << GetLastError();
		throw errorMaker::wruntime_error(&os);
	}

	// Allow 60 seconds for the module to load before we give up
	if (WaitForSingleObject(s, 60 * 1000))
	{
		std::wstringstream os(L"");
		os << "Timeout trying to load module '" << toLoad << "' into remote process";
		throw errorMaker::wruntime_error(&os);
	}
	unsigned char* toRet = getModuleBase(toScanHandle, toLoad);
	if (toRet == NULL)
	{
		std::wstringstream os(L"");
		os << "Failed to load module " << toLoad << " into remote process";
		throw errorMaker::wruntime_error(&os);
	}
	return toRet;
}

DWORD getPIDForProcessByName(TCHAR* toFind)
{
	// Grab the named process as specified at the commandline.
	// This is mostly lifted from https://docs.microsoft.com/en-us/windows/desktop/psapi/enumerating-all-processes
	DWORD aProcesses[1024], cbNeeded, cProcesses;
	unsigned int i;
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		std::wstringstream os(L"");
		os << "Failed EnumProcesses, GetLastError " << GetLastError();
		throw errorMaker::wruntime_error(&os);
	}
	cProcesses = cbNeeded / sizeof(DWORD);

	for (i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] != 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);

			if (NULL == hProcess)
				continue;
			HMODULE hMod;
			DWORD cbNeeded;

			TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
			if (!EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
				continue;

			GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));

			if (_wcsicmp(toFind, szProcessName) == 0)
			{
				CloseHandle(hProcess);
				return aProcesses[i];
			}
			CloseHandle(hProcess);
		}
	}

	std::wstringstream os(L"");
	os << "Cannot find module '" << toFind << "'";
	throw errorMaker::wruntime_error(&os);
}

