#include "pch.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>

#include <vector>
#include <map>

#include "..\driver\public.h"
#include "findPFNDatabase.h"

class statistics {
public:
	statistics()
	{
		scannedPages = ignoredPagesNX = scannedProcesses = modifiedPages = 0;
	}

	unsigned int scannedPages;
	unsigned int ignoredPagesNX;
	unsigned int scannedProcesses;
	unsigned int modifiedPages;
};

class modifiedPage {
public:
	modifiedPage(DWORD newProcessID, wchar_t* newModuleName, void* newPageBase, BYTE newSectionName[8], unsigned long long newSectionOffset);

	unsigned long processID;
	std::wstring moduleName;
	
	unsigned long long pageBase;

	std::wstring sectionName;
	unsigned long long sectionOffset;
};

modifiedPage::modifiedPage(DWORD newProcessID, wchar_t* newModuleName, void* newPageBase, BYTE newSectionName[8], unsigned long long newSectionOffset)
	: processID(newProcessID), moduleName(newModuleName), pageBase((unsigned long long)newPageBase), sectionName(L""), sectionOffset(newSectionOffset)
{
	wchar_t sectionNameCleaned[9];
	memset(sectionNameCleaned, 0, 9 * sizeof(wchar_t));
	wsprintf(sectionNameCleaned, L"%.8s", newSectionName);
	sectionName.append(sectionNameCleaned);
}

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

int scanProcess(HANDLE driverHnd, DWORD targetPID, HANDLE toScanHandle, std::vector<modifiedPage> *resultsOut, statistics* stats)
{
	DWORD cbNeeded;
	int s = EnumProcessModules(toScanHandle, NULL, 0, &cbNeeded);
	if (s == 0)
	{
		printf("Couldn't call EnumProcessModules to get buffer size, gle %d\n", GetLastError());
		return -1;
	}

	HMODULE* moduleList = (HMODULE*)malloc(cbNeeded);
	memset(moduleList, 0, cbNeeded);
	s = EnumProcessModules(toScanHandle, moduleList, cbNeeded, &cbNeeded);
	if (s == 0)
	{
		// This'll happen sometimes if there's a module loaded between our calls. 
		// TODO: we can retry in this case.
		printf("Couldn't call EnumProcessModules to get modules, gle %d.\n", GetLastError());
		return -1;
	}

	for (HMODULE* thisModPtr = &moduleList[0]; thisModPtr < &moduleList[cbNeeded / sizeof(HMODULE)]; thisModPtr++)
	{
		HMODULE thisModule = *thisModPtr;
		TCHAR szModName[MAX_PATH];
		memset(szModName, 0, MAX_PATH * sizeof(TCHAR));
		if (GetModuleFileNameEx(toScanHandle, thisModule, szModName, sizeof(szModName) / sizeof(TCHAR)) == 0)
		{
			printf("GetModuleFileNameEx failed, GLE %d\n", GetLastError());
			continue;
		}
		IMAGE_DOS_HEADER mz;
		SIZE_T bytesRead;
		if (!ReadProcessMemory(toScanHandle, thisModule, &mz, sizeof(IMAGE_DOS_HEADER), &bytesRead))
		{
			printf("Can't read module MZ header\n");
			return -1;
		}
		if (mz.e_magic != IMAGE_DOS_SIGNATURE)
		{
			printf("MZ header not found\n");
			continue;
		}
		IMAGE_NT_HEADERS pe;
		unsigned long long peAddress = (((unsigned long long)thisModule) + mz.e_lfanew);
		if (!ReadProcessMemory(toScanHandle, (void*)peAddress, &pe, sizeof(IMAGE_NT_HEADERS), &bytesRead))
		{
			printf("Can't read module PE header\n");
			return -1;
		}

		if (pe.Signature != IMAGE_NT_SIGNATURE)
		{
			printf("PE header not found\n");
			continue;
		}
		IMAGE_SECTION_HEADER* sect;
		unsigned long long firstSectionAddress = peAddress + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + sizeof(IMAGE_OPTIONAL_HEADER);
		sect = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * pe.FileHeader.NumberOfSections);
		if (!ReadProcessMemory(toScanHandle, (LPCVOID)(firstSectionAddress), sect, sizeof(IMAGE_SECTION_HEADER) * pe.FileHeader.NumberOfSections, &bytesRead))
		{
			printf("Can't read first section of module\n");
			return -1;
		}

		for (unsigned long sectionIndex = 0; sectionIndex < pe.FileHeader.NumberOfSections; sectionIndex++)
		{
			IMAGE_SECTION_HEADER* thisSection = &sect[sectionIndex];
			unsigned long long relocatedSectionBase = thisSection->VirtualAddress + (unsigned long long)thisModule;

			// We are interested only in executable sections.
			// TODO: check that discardable pages are zero'ed out?
			// TODO: check that non-executable pages haven't been made executable?
			if ((thisSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0)
			{
				stats->ignoredPagesNX += (thisSection->SizeOfRawData / 0x1000);
			//	printf("%ls!%s (at %p) is not executable, skipping\n", szModName, thisSection->Name, relocatedSectionBase);
				continue;
			}
			//printf("scanning %ls!%s (at %p), size 0x%08lx\n", szModName, thisSection->Name, relocatedSectionBase, thisSection->SizeOfRawData);

			int dirtyPages = 0;
			int errorPages = 0;
			getPageInfoRequest req;
			req.pageToCheck = relocatedSectionBase;
			// Work out how many pages we will check
			req.numberOfPagesToCheck = thisSection->Misc.VirtualSize / 0x1000;
			if (thisSection->Misc.VirtualSize % 0x1000 != 0)
				req.numberOfPagesToCheck++;
			req.targetPID = targetPID;
				
			getPageInfoResponse* resp = (getPageInfoResponse*)malloc(sizeof(getPageInfoRequest) * req.numberOfPagesToCheck);
			memset(resp, 0x00, sizeof(getPageInfoResponse) * req.numberOfPagesToCheck);

			DWORD bytesRet;
			s = DeviceIoControl(driverHnd, IOCTL_DRIVER_QUERY_VA, &req, sizeof(req), resp, sizeof(getPageInfoResponse) * req.numberOfPagesToCheck, &bytesRet, NULL);
			if (s == 0)
			{
				errorPages++;
				printf("DeviceIoControl failed, GLE %d\n", GetLastError());
				return -1;
			}

			stats->scannedPages += req.numberOfPagesToCheck;

			for (unsigned int n = 0; n < req.numberOfPagesToCheck; n++)
			{
				unsigned long long pageAddress = relocatedSectionBase + (n * 0x1000);

				if (!resp[n].isValid)
				{
					printf("Page at 0x%016llx (%ls!%s) not valid (maybe it's paged out?) 0x%08lx\n", pageAddress, szModName, thisSection->Name, thisSection->Characteristics);
					errorPages++;
					continue;
				}

				if (resp[n].isDirty)
				{
					dirtyPages++;
					resultsOut->push_back(modifiedPage(targetPID, (wchar_t*)szModName, (void*)pageAddress, thisSection->Name, (pageAddress - relocatedSectionBase)));
					stats->modifiedPages++;
				}
			}

//			if (dirtyPages == 0)
//				printf("Module %ls: OK\n", szModName);
//			else
//				printf("Module %ls: detected %d dirty pages!\n", szModName, dirtyPages);
		}
	}

	return 0;
}

int setPFNDatabase(HANDLE driverHnd, unsigned long long PFNDatabaseStart)
{
	setPFNDatabaseRequest req;
	req.offsetToMmPfnDatabaseInNtDllFromExAllocatePoolWithTag = PFNDatabaseStart;

	DWORD bytesRet;
	int s = DeviceIoControl(driverHnd, IOCTL_DRIVER_SET_PFN_DATABASE, &req, sizeof(req), NULL, 0, &bytesRet, NULL);
	if (s == 0)
	{
		printf("Failed to set PFN database to 0x%016llx: GLE %d\n", PFNDatabaseStart, GetLastError());
		return -1;
	}

	return 0;
}

int main()
{
	EnableDebugPrivilege(TRUE);

	HANDLE driverHnd = CreateFile(L"\\\\.\\cowspot", GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (driverHnd == INVALID_HANDLE_VALUE)
	{
		printf("Couldn't open driver device '%ls', gle %d\n", DOS_DEVICE_NAME, GetLastError());
		return -1;
	}

	if (setPFNDatabase(driverHnd, findPFNDatabase()) != 0)
		return -1;

	HANDLE snapshotHnd = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (snapshotHnd == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot failed, GLE %d\n", GetLastError());
		return -1;
	}

	PROCESSENTRY32 proc;
	memset(&proc, 0, sizeof(PROCESSENTRY32));
	proc.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(snapshotHnd, &proc))
	{
		printf("Process32First failed, GLE %d\n", GetLastError());
		return -1;
	}

	statistics stat;
	std::vector<modifiedPage> results;

	unsigned long start = GetTickCount();

	while (Process32Next(snapshotHnd, &proc))
	{
		HANDLE toScanHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.th32ProcessID);
		if (toScanHandle == NULL)
		{
			printf("Couldn't open target process with PID %d ('%ls'), gle %d\n", proc.th32ProcessID, proc.szExeFile, GetLastError());
			continue;
		}

		stat.scannedProcesses++;
		if (scanProcess(driverHnd, proc.th32ProcessID, toScanHandle, &results, &stat) != 0)
			printf("Failed to scan process '%ls'\n", proc.szExeFile);
		// else
		//	printf("Scanned process '%ls'\n", proc.szExeFile);
		CloseHandle(toScanHandle);
	}

	CloseHandle(snapshotHnd);

	unsigned long end = GetTickCount();

	printf("Scan took %dms\n", (end - start));

	// Print some stats and the results.
	printf("Scanned %d pages, ignored %d NX pages (total %d). Found %d modified pages.\n", stat.scannedPages, stat.ignoredPagesNX, stat.ignoredPagesNX + stat.scannedPages, stat.modifiedPages);
	for (unsigned int n = 0; n < results.size(); n++)
	{
		modifiedPage thisModifiedPage = results[n];
		printf("PID %04d module '%ls', section %S, offset 0x%08llux\n", thisModifiedPage.processID, thisModifiedPage.moduleName.c_str(), thisModifiedPage.sectionName.c_str(), thisModifiedPage.sectionOffset);
	/*
		HANDLE toScanHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, thisModifiedPage.processID);
		if (toScanHandle == NULL)
		{
			printf("Couldn't open target process with PID %d ('%ls'), gle %d\n", proc.th32ProcessID, proc.szExeFile, GetLastError());
			continue;
		}
		SIZE_T bytesRead;
		unsigned char* pageContents[0x2000];
		memset(pageContents, 0, 0x2000);
		if (!ReadProcessMemory(toScanHandle, (LPCVOID)thisModifiedPage.pageBase, pageContents, 0x2000, &bytesRead))
		{
			printf("ReadProcessMemory failed\n");
			continue;
		}
		
		for (unsigned int n = 0; n < 0x2001; n++)
		{
			printf("0x%02hhx ", (unsigned)pageContents[n]);
			if (n % 0x10 == 0)
				printf("\n0x%08lx: ", n);
		}
		CloseHandle(toScanHandle);*/
	}

	return 0;
}
