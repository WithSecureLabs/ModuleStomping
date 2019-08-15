#pragma once

#include <string>
#include <vector>
#include <map>

class section
{
public:
	section();
	section(IMAGE_SECTION_HEADER* hdr);

	std::wstring name;
	DWORD Characteristics;
	DWORD PhysicalAddress;
	DWORD VirtualAddress;
	DWORD VirtualSize;
};

class relocation
{
public:
	unsigned long long targetSite;
	unsigned long long fixedUpValue;
	unsigned int size;

	relocation(unsigned long long newTargetSite, unsigned long long newFixedUpValue, unsigned int newSize);
};

class exportedFunc
{
public:
	exportedFunc(std::wstring functionName, unsigned long long functionPointerSite, unsigned long long functionPointerRVA);
	exportedFunc(std::wstring functionName, std::wstring forwardedModuleName, std::wstring forwardedFunctionName);

	std::wstring functionName;
	unsigned long long functionPointerSite;
	unsigned long long functionPointerRVA;
	std::wstring forwardedFunctionName;
	std::wstring forwardedModuleName;
	BOOL isForwarded;
};

class importedFunc : public exportedFunc
{
public:
	importedFunc(std::wstring moduleName, std::wstring functionName, unsigned long long functionPointerSite, unsigned long long functionPointerRVA);

	std::wstring moduleName;
};

class moduleInMemory
{
public:
	moduleInMemory(HANDLE targetProcessHandle, void* targetModuleBase);
	moduleInMemory(HANDLE targetProcessHandle, std::wstring targetModuleName);

	void injectThread(unsigned long long startRVA, unsigned long long* args, unsigned int argCount, bool waitForReturn = true);
	section* getSectionForAddress(unsigned long long toFind);
	section* getSectionByName(std::wstring toFind);
	void readFromModule(unsigned long long srcAddress, void* outBuf, SIZE_T bytesToRead);
	std::wstring readStringFromModule(unsigned long long srcAddress);
	void writeToModule(void* srcData, unsigned long long destAddress, SIZE_T bytesToWrite);
	importedFunc* getImport(std::wstring moduleName, std::wstring functionName);
	exportedFunc* getExport(std::wstring functionName);
	BOOL hasExport(std::wstring functionName);
	void markCFGValid(unsigned long long ptrToMarkValid); 
	unsigned long long resolveExport(std::wstring importName);
	unsigned long long locateROPGadget(unsigned char* bytesToFind, unsigned int bytesToFindLen);

	unsigned long long entrypoint;
	std::vector<section> sections;
	std::vector<importedFunc> imports;
	std::vector<exportedFunc> exports;
	std::vector<unsigned long long> TLSCallbacks;
	std::vector<relocation> relocs;
	bool hasImports;
	bool hasExports;
	bool hasTLS;

	void* targetModuleBase;
	unsigned long long sizeOfImage;
	unsigned long long preferredBaseAddress;
private:
	void commonInit();
		
	HANDLE targetProcess;

	typedef BOOL(*SetProcessValidCallTargetsType)(HANDLE hProcess, PVOID VirtualAddress, SIZE_T RegionSize, ULONG NumberOfOffsets, PCFG_CALL_TARGET_INFO OffsetInformation);
	SetProcessValidCallTargetsType SetProcessValidCallTargets_;

	moduleInMemory();

	void processModule();

	void setPEFeatures(IMAGE_NT_HEADERS *pe);
	void processModuleImports(IMAGE_NT_HEADERS *pe);
	void processModuleExports(IMAGE_NT_HEADERS *pe);
	void processModuleRelocs(IMAGE_NT_HEADERS *pe);
	void processModuleTLSCallbacks(IMAGE_NT_HEADERS *pe);


	class ROPGadgetInfo
	{
	public:
		ROPGadgetInfo(void* newModuleBase, unsigned char* newBytesToFind, unsigned int newBytesToFindLen) : moduleBase(newModuleBase), bytesToFind(newBytesToFind), bytesToFindLen(newBytesToFindLen)
		{

		}

		bool operator<(const ROPGadgetInfo& other) const
		{
			if (moduleBase != other.moduleBase)
				return moduleBase > other.moduleBase;
			if (bytesToFindLen != other.bytesToFindLen)
				return bytesToFindLen > other.bytesToFindLen;
			return memcmp(bytesToFind, other.bytesToFind, bytesToFindLen);
		}

		void* moduleBase;
		unsigned char* bytesToFind;
		unsigned int bytesToFindLen;
	};

	static std::map<ROPGadgetInfo, unsigned long long> gadgetCache;
	unsigned long long locateROPGadgetUncached(ROPGadgetInfo* toFind);
	unsigned long long addModuleBase(unsigned long long toAdd);

	void writeToModuleWithoutPermissionCheck(void* srcData, unsigned long long dstBased, SIZE_T bytesToWrite);
	friend class moduleFromDisk;
};

class moduleFromDisk : public moduleInMemory
{
public:
	moduleFromDisk(LPCWSTR filename);
	~moduleFromDisk();
private:
	HANDLE fhnd;
	void readFromFile(int pos, void* outbuf, int size);
};


class errorMaker
{
public:
	static std::runtime_error wruntime_error(std::wstring unicodeMsg);
	static std::runtime_error wruntime_error(std::wstringstream* unicodeMsgStream);
};

class stackBuilder
{
public:
	stackBuilder(HANDLE newTargetProcess, unsigned long long newStackSize);
	void push(unsigned long long newVal);
	unsigned long long writeToProcess();
	unsigned long long getPtrToTopOfStack();
private:
	unsigned long long* stack;
	unsigned long long stackSizeBytes;
	unsigned long long stackSizeULLs;
	unsigned long long stackPointerULLs;
	HANDLE targetProcess;
	unsigned long long stackInTargetAddressSpace;
};