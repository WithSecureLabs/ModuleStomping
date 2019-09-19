#include "stdafx.h"

#include <exception>
#include <sstream>
#include <vector>
#include <map>
#include <iostream>

#include "moduleManipulation.h"
#include "public.h"

#include <string>
#include <locale>
#include <codecvt>
#include <tlhelp32.h>

std::map<moduleInMemory::ROPGadgetInfo, unsigned long long> moduleInMemory::gadgetCache;

section::section()
{
	name = std::wstring(L"(none)");
	Characteristics = VirtualAddress = VirtualSize = 0;
};

section::section(IMAGE_SECTION_HEADER* hdr)
{
	// Convert the section name to unicode so we can use it. 
	// Don't forget that the section name doesn't need to be null-terminated - if it is
	// 8 bytes long then we must not read any further.
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring secName = std::wstring(converter.from_bytes((char*)hdr->Name, (char*)&hdr->Name[7]));
	size_t nullPos = secName.find(L'\0');
	if (nullPos != secName.npos)
		secName = secName.substr(0, nullPos);
	name = secName;
	Characteristics = hdr->Characteristics;
	PhysicalAddress = hdr->Misc.PhysicalAddress;
	VirtualAddress = hdr->VirtualAddress;
	VirtualSize = hdr->Misc.VirtualSize;
}

relocation::relocation(unsigned long long newTargetSite, unsigned long long newFixedUpValue, unsigned int newSize)
{
	targetSite = newTargetSite;
	fixedUpValue = newFixedUpValue;
	size = newSize;
}

exportedFunc::exportedFunc(std::wstring functionName, std::wstring forwardedModuleName, std::wstring forwardedFunctionName)
{
	this->functionName = functionName;
	this->functionPointerSite = 0;
	this->functionPointerRVA = 0;
	this->forwardedModuleName = forwardedModuleName;
	this->forwardedFunctionName = forwardedFunctionName;
	isForwarded = TRUE;
};

exportedFunc::exportedFunc(std::wstring functionName, unsigned long long functionPointerSite, unsigned long long functionPointerRVA)
{
	this->functionName = functionName;
	this->functionPointerSite = functionPointerSite;
	this->functionPointerRVA = functionPointerRVA;
	isForwarded = FALSE;
};


importedFunc::importedFunc(std::wstring moduleName, std::wstring functionName, unsigned long long functionPointerSite, unsigned long long functionPointerRVA)
	: exportedFunc(functionName, functionPointerSite, functionPointerRVA)
{
	this->moduleName = moduleName;
};

moduleInMemory::moduleInMemory(HANDLE targetProcessHandle, std::wstring targetModuleName) : targetProcess(targetProcessHandle)
{
	unsigned char* moduleBase = getModuleBase(targetProcess, targetModuleName.c_str());
	if (moduleBase == NULL)
	{
		std::wstringstream os(L"");
		os << "Failed to find module " << targetModuleName;
		throw errorMaker::wruntime_error(os.str());
	}
	targetModuleBase = moduleBase;

	commonInit();
}

moduleInMemory::moduleInMemory(HANDLE targetProcessHandle, void* targetModuleBase) : targetProcess(targetProcessHandle), targetModuleBase(targetModuleBase)
{
	commonInit();
}

void moduleInMemory::commonInit()
{
	// Load an unexported function we need in order to disable CFG
	SetProcessValidCallTargets_ = (SetProcessValidCallTargetsType)GetProcAddress(LoadLibrary(L"Kernelbase"), "SetProcessValidCallTargets");
	if (SetProcessValidCallTargets_ == NULL)
		throw std::exception("Cannot resolve Kernelbase!SetProcessValidCallTargets\n");

	processModule();
}

unsigned long long moduleInMemory::resolveExport(std::wstring importName)
{
	exportedFunc* exp = this->getExport(importName.c_str());

	if (!exp->isForwarded)
		return exp->functionPointerRVA + ((unsigned long long)this->targetModuleBase);

	moduleInMemory* forwardModule = NULL;
	while (exp->isForwarded)
	{
		moduleInMemory* tmp2 = new moduleInMemory(targetProcess, getModuleBase(targetProcess, exp->forwardedModuleName.c_str()));
		exp = tmp2->getExport(exp->forwardedFunctionName);
		if (forwardModule != NULL)
			delete forwardModule;
		forwardModule = tmp2;
	}
	unsigned long long toRet;
	toRet = exp->functionPointerRVA + ((unsigned long long)forwardModule->targetModuleBase);
	delete forwardModule;
	return toRet;
}

unsigned long long moduleInMemory::locateROPGadget(unsigned char* bytesToFind, unsigned int bytesToFindLen)
{
	ROPGadgetInfo toFind(this->targetModuleBase, bytesToFind, bytesToFindLen);

	// First, try our cache
	std::map<ROPGadgetInfo, unsigned long long>::iterator it = gadgetCache.find(toFind);
	if (it != gadgetCache.end())
	{
		// It's in the cache, so try that. The cache might be dirty so do check it before we return, and fall back to searching again if it
		// isn't what we expect.
		unsigned char* buf = (unsigned char*)malloc(toFind.bytesToFindLen);
		readFromModule((*it).second - ((unsigned long long)targetModuleBase), buf, bytesToFindLen);
		if (memcmp(buf, toFind.bytesToFind, bytesToFindLen) == 0)
			return (*it).second;
	}
	// Nope, not in the cache (or the cache is dirty).
	unsigned long long toRet = locateROPGadgetUncached(&toFind);
	gadgetCache.insert(std::pair<ROPGadgetInfo, unsigned long long>(toFind, toRet));
	return toRet;
}

unsigned long long moduleInMemory::locateROPGadgetUncached(ROPGadgetInfo* toFind)
{
	for (unsigned int sectIdx = 0; sectIdx < sections.size(); sectIdx++)
	{
		section* sect = &sections[sectIdx];
		if (!(sect->Characteristics & IMAGE_SCN_MEM_EXECUTE))
			continue;

		unsigned char* buf = (unsigned char*)malloc(toFind->bytesToFindLen);
		for (unsigned int bytePtr = 0; bytePtr < sect->VirtualSize - toFind->bytesToFindLen; bytePtr++)
		{
			readFromModule(sect->VirtualAddress + bytePtr, buf, toFind->bytesToFindLen);
			if (memcmp(buf, toFind->bytesToFind, toFind->bytesToFindLen) == 0)
				return sect->VirtualAddress + bytePtr + ((unsigned long long)targetModuleBase);
		}
	}
	throw std::exception("Cannot locate ROP gadget :(");
}

unsigned long long moduleInMemory::addModuleBase(unsigned long long toAdd)
{
	return (((unsigned long long)targetModuleBase) + toAdd);
}

void moduleInMemory::injectThread(unsigned long long startRVA, unsigned long long* args, unsigned int argCount, bool waitForReturn)
{
	// The based address we're calling
	unsigned long long targetAddress = addModuleBase(startRVA);

	// Allocate a stack for our injected thread.
	stackBuilder stack(targetProcess, 0x10000);

	// We will need to find a couple functions from kernelbase.dll, which our "shellcode" will use.
	moduleInMemory kernelBase(targetProcess, L"kernelbase.dll");
	unsigned long long exitThread = kernelBase.resolveExport(L"ExitThread");

	stack.push(exitThread);
	stack.push(targetAddress);

	stack.writeToProcess();

	// Make a new thread, suspended. We will set its stack and RIP values later on, before we resume it. We just supply bogus ones here.
	DWORD tid;
	HANDLE s = CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)NULL, NULL, CREATE_SUSPENDED, &tid);
	if (!s)
		throw std::runtime_error("CreateRemoteThread failed");

	// Somewhat annoyingly, we can't alter the stack pointer via SetThreadContext until the new thread has been resumed. We need to use a 
	// ROP-style stack pivot in order to set it.
	// We use this gadget:
	// 49 8b e3		mov rsp, r11
	// 41 5e		pop r14
	// c3			ret 
	unsigned char gadgetCode[] = {
		0x49, 0x8b, 0xe3,
		0x41, 0x5e,
		0xc3
	};
	unsigned long long stackPivot = kernelBase.locateROPGadget(gadgetCode, sizeof(gadgetCode));

	// We can now set our new thread to the RIP location we want, and set registers with any arguments.
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(s, &ctx))
		throw std::runtime_error("GetThreadContext failed");

	if (argCount > 0)
		ctx.Rcx = args[0];
	if (argCount > 1)
		ctx.Rdx = args[1];
	if (argCount > 2)
		ctx.R8 = args[2];
	if (argCount > 3)
		ctx.R9 = args[3];
	ctx.R11 = stack.getPtrToTopOfStack() - 8;
	ctx.Rip = stackPivot;

	SetThreadContext(s, &ctx);

	ResumeThread(s);

	if (waitForReturn)
		WaitForSingleObject(s, INFINITE);
}

void moduleInMemory::markCFGValid(unsigned long long ptrToMarkValid)
{
	CFG_CALL_TARGET_INFO info;
	info.Flags = CFG_CALL_TARGET_VALID;
	info.Offset = ptrToMarkValid;

	if (!SetProcessValidCallTargets_(targetProcess, (void*)targetModuleBase, sizeOfImage, 1, &info))
		throw std::exception("SetProcessValidCallTargets failed");
}

section* moduleInMemory::getSectionForAddress(unsigned long long toFind)
{
	unsigned long long RVA = toFind - (unsigned long long)targetModuleBase;
	for (unsigned int sectIndex = 0; sectIndex < sections.size(); sectIndex++)
	{
		section sect = sections[sectIndex];
		if (RVA >= sect.VirtualAddress &&
			RVA <= sect.VirtualAddress + sect.VirtualSize)
		{
			return &sections[sectIndex];
		}
	}

	return NULL;
}

section* moduleInMemory::getSectionByName(std::wstring toFind)
{
	for (unsigned int sectIndex = 0; sectIndex < sections.size(); sectIndex++)
	{
		section sect = sections[sectIndex];
		if (sect.name == toFind.c_str())
			return &sections[sectIndex];
	}
	return NULL;
}

void moduleInMemory::readFromModule(unsigned long long srcAddress, void* outBuf, SIZE_T bytesToRead)
{
	SIZE_T bytesActuallyRead;
	int s = ReadProcessMemory(targetProcess, &((unsigned char*)targetModuleBase)[srcAddress], outBuf, bytesToRead, &bytesActuallyRead);
	if (!s)
	{
		std::ostringstream os("");
		os << "Failed ReadProcessMemory of " << bytesToRead << " bytes starting from " << std::hex << targetModuleBase << "+" << srcAddress <<
			" : read only " << std::dec << bytesActuallyRead << " of " << bytesToRead << ", GLE " << GetLastError();
		throw std::runtime_error(os.str());
	}
}

std::wstring moduleInMemory::readStringFromModule(unsigned long long srcAddress)
{
	std::wostringstream os;

	// Pretty ineffecient since we read a byte at a time.
	int n = 0;
	char moduleNameLetter;
	do
	{
		readFromModule(srcAddress + n, &moduleNameLetter, 1);
		if (moduleNameLetter != 0)
			os << moduleNameLetter;
		n++;
	} while (moduleNameLetter != 0);

	return os.str();
}

void moduleInMemory::writeToModule(void* srcData, unsigned long long destAddress, SIZE_T bytesToWrite)
{
	unsigned long long srcCursor = (unsigned long long)srcData;
	unsigned long long dstBased = (unsigned long long)&((unsigned char*)targetModuleBase)[destAddress];

	// Write a page at a time, checking and changing permissions if needed.
	while (bytesToWrite > 0)
	{
		unsigned long long toWriteThisPage = bytesToWrite;
		if (toWriteThisPage > 0x1000)
			toWriteThisPage = 0x1000;

		// printf("Write 0x%08llx bytes at 0x%016llx\n", toWriteThisPage, dstBased);

		// Make it writable
		DWORD oldPerms;
		if (!VirtualProtectEx(targetProcess, (PVOID*)dstBased, toWriteThisPage, PAGE_EXECUTE_READWRITE, &oldPerms))
			throw std::runtime_error("oh no");

		writeToModuleWithoutPermissionCheck((void*)srcCursor, dstBased, toWriteThisPage);

		// Restore the previous permissions
		if (!VirtualProtectEx(targetProcess, (PVOID*)dstBased, toWriteThisPage, oldPerms, &oldPerms))
			throw std::runtime_error("oh no");

		if (bytesToWrite < toWriteThisPage)
			break;
		bytesToWrite -= toWriteThisPage;
		srcCursor += toWriteThisPage;
		dstBased += toWriteThisPage;
	}
}

importedFunc* moduleInMemory::getImport(std::wstring moduleName, std::wstring functionName)
{
	for (unsigned int n = 0; n < imports.size(); n++)
	{
		if ((imports[n].functionName == functionName) &&
			(imports[n].moduleName == moduleName))
			return &imports[n];
	}
	return NULL;
}

BOOL moduleInMemory::hasExport(std::wstring functionName)
{
	for (unsigned int n = 0; n < exports.size(); n++)
	{
		if (exports[n].functionName == functionName)
			return true;
	}
	return false;
}

exportedFunc* moduleInMemory::getExport(std::wstring functionName)
{
	for (unsigned int n = 0; n < exports.size(); n++)
	{
		if (exports[n].functionName == functionName)
			return &exports[n];
	}
	std::wstringstream os(L"");
	os << "Failed to find export '" << functionName << "' ";
	throw errorMaker::wruntime_error(&os);
}

moduleInMemory::moduleInMemory()
{

}

void moduleInMemory::processModule()
{
	IMAGE_DOS_HEADER mz;
	readFromModule(0, &mz, sizeof(mz));
	if (mz.e_magic != IMAGE_DOS_SIGNATURE)
		throw std::runtime_error("Module has incorrect MZ signature");

	IMAGE_NT_HEADERS pe;
	readFromModule(mz.e_lfanew, &pe, sizeof(pe));
	if (pe.Signature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("Module has incorrect PE signature");

	this->entrypoint = pe.OptionalHeader.AddressOfEntryPoint;

	// Sections start directly after the PE.
	unsigned long long sectPtr = mz.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pe.FileHeader.SizeOfOptionalHeader;

	for (unsigned int sectionIndex = 0; sectionIndex < pe.FileHeader.NumberOfSections; sectionIndex++)
	{
		IMAGE_SECTION_HEADER sect;
		readFromModule(sectPtr, &sect, sizeof(IMAGE_SECTION_HEADER));
		sections.push_back(section(&sect));
		sectPtr += sizeof(IMAGE_SECTION_HEADER);
	}
	setPEFeatures(&pe);
	processModuleImports(&pe);
	processModuleExports(&pe);
	processModuleRelocs(&pe);
	processModuleTLSCallbacks(&pe);
}

void moduleInMemory::setPEFeatures(IMAGE_NT_HEADERS *pe)
{
	preferredBaseAddress = pe->OptionalHeader.ImageBase;
	sizeOfImage = pe->OptionalHeader.SizeOfImage;
	unsigned int numOfDataDirectories = pe->OptionalHeader.NumberOfRvaAndSizes;
	hasImports = (numOfDataDirectories - 1 >= IMAGE_DIRECTORY_ENTRY_IMPORT);
	hasExports = (numOfDataDirectories - 1 >= IMAGE_DIRECTORY_ENTRY_EXPORT);
	hasTLS = (numOfDataDirectories - 1 >= IMAGE_DIRECTORY_ENTRY_TLS);
	// Some compilers emit a zero'ed out TLS data directory to signify the absence of TLS data.
	if (hasTLS)
	{
		if (pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0)
			hasTLS = false;
	}
}

void moduleInMemory::processModuleImports(IMAGE_NT_HEADERS *pe)
{
	if (!hasImports)
		return;

	unsigned long long impDescPtr;
	impDescPtr = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (impDescPtr == 0)
		return;
	while (true)
	{
		IMAGE_IMPORT_DESCRIPTOR impDesc;
		readFromModule(impDescPtr, &impDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		if (impDesc.Name == 0)
			break;

		std::wstring importedModuleName = readStringFromModule((unsigned long long)impDesc.Name);
		// TODO: detect / handle imports by ordinal, forwarded imports
		DWORD oft = impDesc.OriginalFirstThunk;
		DWORD ft = impDesc.FirstThunk;
		do
		{
			DWORD thunkDataRVA;
			readFromModule(oft, (void*)&thunkDataRVA, sizeof(DWORD));
			if (thunkDataRVA == 0)
				break;

			unsigned long long pointerSite = ft + pe->OptionalHeader.ImageBase;

			std::wstring importedFunctionName = readStringFromModule((unsigned long long)thunkDataRVA + 2);
//				printf("Function import from module '%s' of function '%s': pointer is stored at RVA 0x%08lux\n", importedModuleName.c_str(), importedFunctionName.c_str(), ft);
			importedFunc f(importedModuleName, importedFunctionName, pointerSite, (unsigned long long)ft);
			imports.push_back(f);
			oft += 8;
			ft += 8;
		} while (true);

		impDescPtr += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
}

void moduleInMemory::processModuleExports(IMAGE_NT_HEADERS *pe)
{
	if (!hasExports)
		return;

	unsigned long long expDescPtr;
	unsigned long long expDescLimit;
	expDescPtr = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	expDescLimit = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (expDescPtr == 0)
		return;
	IMAGE_EXPORT_DIRECTORY expDesc;
	readFromModule(expDescPtr, &expDesc, sizeof(IMAGE_EXPORT_DIRECTORY));
	if (expDesc.Name == 0)
		return;

	std::wstring exportName = readStringFromModule((unsigned long long)expDesc.Name);
	unsigned int functionCount = 0;
	DWORD functions = expDesc.AddressOfFunctions;
	// Read name ordinals into memory, it makes things simpler
	USHORT* nameOrdinals = (USHORT*)malloc(expDesc.NumberOfFunctions * sizeof(USHORT));
	readFromModule(expDesc.AddressOfNameOrdinals, nameOrdinals, expDesc.NumberOfFunctions * sizeof(USHORT));

	for (unsigned int funcIdx = 0; funcIdx < expDesc.NumberOfNames; funcIdx++)
	{
		DWORD funcNameRVA = expDesc.AddressOfNames + (funcIdx * sizeof(DWORD));
		readFromModule(funcNameRVA, (void*)&funcNameRVA, sizeof(DWORD));

		unsigned long long exportedCodePtr = expDesc.AddressOfFunctions + (nameOrdinals[funcIdx] * sizeof(DWORD));
		unsigned long long exportedCodeRVA = 0;

		readFromModule(exportedCodePtr, (void*)&exportedCodeRVA, sizeof(DWORD));
		unsigned long long exportedCode = exportedCodeRVA + (unsigned long long)targetModuleBase;
		std::wstring exportedFunctionName = readStringFromModule(funcNameRVA);

		// If the exported function is outside the export table, it's a forwarded export.
		if (exportedCodeRVA >= expDescPtr && exportedCodeRVA < expDescLimit)
		{
			std::wstring forwardString = readStringFromModule(exportedCodeRVA);
			SIZE_T dotPos = forwardString.find(L".");
			std::wstring forwardedModule = forwardString.substr(0, dotPos);
			std::wstring forwardedFunction = forwardString.substr(dotPos + 1, forwardString.size());
			exportedFunc f(exportedFunctionName, forwardedModule, forwardedFunction);
			exports.push_back(f);
		}
		else
		{
			exportedFunc f(exportedFunctionName, exportedCode, exportedCodeRVA);
			exports.push_back(f);
		}
	};
	free(nameOrdinals);
}

void moduleInMemory::processModuleRelocs(IMAGE_NT_HEADERS *pe)
{
	unsigned long long relocsPtr = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (relocsPtr == NULL)
		return;

	unsigned long long endOfRelocsPtr = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	while (relocsPtr < endOfRelocsPtr)
	{
		IMAGE_BASE_RELOCATION relocBlock;
		readFromModule(relocsPtr, &relocBlock, sizeof(IMAGE_BASE_RELOCATION));
		unsigned long long blockData = relocsPtr + sizeof(IMAGE_BASE_RELOCATION);
		for (unsigned int relocIndex = 0; relocIndex < (relocBlock.SizeOfBlock - 8) / sizeof(WORD); relocIndex++)
		{
			unsigned short relocAndType;
			readFromModule(blockData, &relocAndType, sizeof(unsigned short));

			unsigned char relocType = (relocAndType >> 12);
			unsigned short relocVal = (relocAndType & 0x0fff);
			if (relocType == IMAGE_REL_BASED_ABSOLUTE)
			{
				// .. nothing to do for this type
			}
			else if (relocType == IMAGE_REL_BASED_DIR64)
			{
				unsigned long long relocAddr = relocBlock.VirtualAddress + relocVal;
				// unsigned long long toAdd = ((unsigned long long)targetModuleBase) - pe->OptionalHeader.ImageBase;

				relocs.push_back(relocation(relocAddr, 0, sizeof(unsigned long long)));
			}
			else
			{
				throw std::runtime_error("Unrecognised relocation type");
			}
			relocsPtr += 2;
			blockData += 2;
		}
		relocsPtr += sizeof(IMAGE_BASE_RELOCATION);
	}
}

void moduleInMemory::processModuleTLSCallbacks(IMAGE_NT_HEADERS *pe)
{
	if (!hasTLS)
		return;

	unsigned long long tlsTablePtr = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	if (pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != sizeof(IMAGE_TLS_DIRECTORY))
		throw std::runtime_error("Module has TLS entry not of sizeof(IMAGE_TLS_DIRECTORY)");

	IMAGE_TLS_DIRECTORY tlsDir;
	readFromModule(tlsTablePtr, &tlsDir, sizeof(IMAGE_TLS_DIRECTORY));

	unsigned long long callbackCursor = tlsDir.AddressOfCallBacks - ((unsigned long long)targetModuleBase);
	while (true)
	{
		unsigned long long callbackAddress;
		readFromModule(callbackCursor, &callbackAddress, sizeof(unsigned long long));
		if (callbackAddress == NULL)
			break;
		TLSCallbacks.push_back(callbackAddress - ((unsigned long long)targetModuleBase));
		callbackCursor += sizeof(unsigned long long);
	}

}

void moduleInMemory::writeToModuleWithoutPermissionCheck(void* srcData, unsigned long long dstBased, SIZE_T bytesToWrite)
{
	SIZE_T bytesActuallyWritten;
	int s = WriteProcessMemory(targetProcess, (void*)dstBased, srcData, bytesToWrite, &bytesActuallyWritten);
	if (!s)
	{
		std::ostringstream os("");
		os << "Failed WriteProcessMemory of " << bytesToWrite << " bytes starting from " << std::hex << dstBased << 
			" : wrote only " << std::dec << bytesActuallyWritten << " of " << bytesToWrite << ", GLE " << GetLastError();
		throw std::runtime_error(os.str());
	}
}

moduleFromDisk::moduleFromDisk(LPCWSTR filename)
{
	fhnd = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (fhnd == INVALID_HANDLE_VALUE)
	{
		std::ostringstream os("");
		os << "Unable to open file '" << filename << "', GLE reported error code " << GetLastError();
		throw std::runtime_error(os.str());
	}

	IMAGE_DOS_HEADER mz;
	readFromFile(0, &mz, sizeof(mz));
	if (mz.e_magic != IMAGE_DOS_SIGNATURE)
		throw std::runtime_error("Module has incorrect MZ signature");

	IMAGE_NT_HEADERS pe;
	readFromFile(mz.e_lfanew, &pe, sizeof(pe));
	if (pe.Signature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("Module has incorrect PE signature");

	this->targetProcess = GetCurrentProcess();
	this->entrypoint = pe.OptionalHeader.AddressOfEntryPoint;

	// Alloc enough memory for the whole image
	this->targetModuleBase = VirtualAlloc((void*)pe.OptionalHeader.ImageBase, pe.OptionalHeader.SizeOfImage, MEM_RESERVE + MEM_COMMIT, PAGE_READWRITE);
	if (this->targetModuleBase == NULL)
		throw std::runtime_error("Unable to allocate space for image");
	if (this->targetModuleBase != (void*)pe.OptionalHeader.ImageBase)
		throw std::runtime_error("Couldn't load image at preferred base address");

	// Load the headers at the start of the loaded range
	readFromFile(0, this->targetModuleBase, pe.OptionalHeader.SizeOfHeaders);

	// Load each section
	unsigned char* sectionPtr = (unsigned char*)this->targetModuleBase;
	sectionPtr += mz.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pe.FileHeader.SizeOfOptionalHeader;
	IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)sectionPtr;
	for (unsigned int sectionIndex = 0; sectionIndex < pe.FileHeader.NumberOfSections; sectionIndex++)
	{
		IMAGE_SECTION_HEADER sect;
		memcpy(&sect, &sections[sectionIndex], sizeof(IMAGE_SECTION_HEADER));
		section newSect(&sect);
		this->sections.push_back(newSect);
	}

	setPEFeatures(&pe);

	// load section data
	for (unsigned int sectionIndex = 0; sectionIndex < pe.FileHeader.NumberOfSections; sectionIndex++)
		readFromFile(sections[sectionIndex].PointerToRawData, (void*)(sections[sectionIndex].VirtualAddress + pe.OptionalHeader.ImageBase), sections[sectionIndex].SizeOfRawData);

	// And finish the load.
	IMAGE_NT_HEADERS* pePtr = (IMAGE_NT_HEADERS*)(((unsigned char*)this->targetModuleBase) + mz.e_lfanew);
	processModuleImports(pePtr);
	processModuleExports(pePtr);
	processModuleRelocs(&pe);
	processModuleTLSCallbacks(pePtr);
}

moduleFromDisk::~moduleFromDisk()
{
	CloseHandle(fhnd);
}

void moduleFromDisk::readFromFile(int pos, void* outbuf, int size)
{
	DWORD bytesRead;
	SetFilePointer(fhnd, pos, 0, FILE_BEGIN);
	if (!ReadFile(fhnd, outbuf, size, &bytesRead, NULL))
		throw std::runtime_error("ReadFile failed");

	if (bytesRead != size)
		throw std::runtime_error("short read");
}

// FIXME: do these classes violate const safety?
std::runtime_error errorMaker::wruntime_error(std::wstring unicodeMsg)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::string messageAnsi = converter.to_bytes(unicodeMsg);
	return std::runtime_error(messageAnsi);
}
std::runtime_error errorMaker::wruntime_error(std::wstringstream* unicodeMsgStream)
{
	return wruntime_error(unicodeMsgStream->str());
}

stackBuilder::stackBuilder(HANDLE newTargetProcess, unsigned long long newStackSize) : targetProcess(newTargetProcess), stackSizeBytes(newStackSize)
{
	stackInTargetAddressSpace = (unsigned long long)VirtualAllocEx(targetProcess, NULL, stackSizeBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (stackInTargetAddressSpace == NULL)
	{
		std::wstringstream os(L"");
		os << "Failed to allocate " << std::hex << stackSizeBytes << " bytes for stack: GetLastError is " << std::dec << GetLastError();
		throw errorMaker::wruntime_error(&os);
	}

	// We do all the stack building in our own processess address space, and then copy it
	// to the target in writeToProcess.
	stack = (unsigned long long*)calloc(stackSizeBytes, 1);
	stackSizeULLs = stackSizeBytes / sizeof(unsigned long long);
	stackPointerULLs = stackSizeULLs;

	// We will put our data near the top of this stack, allowing some extra headroom.
	if (stackSizeULLs < 20)
		throw std::runtime_error("stackSize: too small stack space");
	stackPointerULLs -= 20;
}

void stackBuilder::push(unsigned long long newVal)
{
	if (stackPointerULLs == 0)
		throw std::runtime_error("stackSize: stack is too small to push anything more");

	stackPointerULLs--;
	stack[stackPointerULLs] = newVal;
}

unsigned long long stackBuilder::writeToProcess()
{
	SIZE_T written = 0;
	if (!WriteProcessMemory(targetProcess, (void*)stackInTargetAddressSpace, stack, stackSizeBytes, &written) || written != stackSizeBytes)
	{
		std::wstringstream os(L"");
		os << "Failed to WriteProcessMemory; wrote " << written << " of " << stackSizeBytes << " bytes; GetLastError is " << GetLastError();
		throw errorMaker::wruntime_error(&os);
	}

	return stackInTargetAddressSpace;
}

unsigned long long stackBuilder::getPtrToTopOfStack()
{
	return stackInTargetAddressSpace + (stackPointerULLs * sizeof(unsigned long long));
}
