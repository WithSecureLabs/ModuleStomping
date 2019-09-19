#include "pch.h"
#include <stdio.h>
#include <windows.h>
#include <dia2.h>

#include <string>

unsigned long findSymbol(IDiaSymbol* g_pGlobalSymbol, const wchar_t* symbolName);

unsigned long long findPFNDatabase()
{
	IDiaDataSource *g_pDiaDataSource;
	IDiaSession *g_pDiaSession;
	IDiaSymbol *g_pGlobalSymbol;

	// Assemble the path to ntoskrnl.exe. It'll be in System32.
	wchar_t systemDir[MAX_PATH];
	GetSystemDirectory(systemDir, MAX_PATH);
	std::wstring exeFilename(L"");
	exeFilename.append(systemDir);
	exeFilename.append(L"\\ntoskrnl.exe");

	// Assemble the symbol path. We use the current directory as a cache path.
	wchar_t curPath[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, curPath);
	std::wstring symPath(L"");
	symPath.append(L"srv*");
	symPath.append(curPath);
	symPath.append(L"*http://msdl.microsoft.com/download/symbols");

	HRESULT hr = CoInitialize(NULL);

	hr = CoCreateInstance(__uuidof(DiaSource), NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&g_pDiaDataSource);

	if (FAILED(hr))
	{
		printf("CoCreateInstance failed for UUID of IDiaDataSource - HRESULT is %08X\n", hr);
		if (hr == REGDB_E_CLASSNOTREG)
			printf("This means the DIA class is not registered. You may need to register it via regsvr32.\n");
		return false;
	}

	HMODULE symSrv = LoadLibrary(L"symsrv.dll");
	if (symSrv == NULL)
	{
		printf("symsrv.dll not found. Please install a copy in your PATH.\n");
		return false;
	}

	printf("Loading PDBs..\n");
	hr = g_pDiaDataSource->loadDataForExe(exeFilename.c_str(), symPath.c_str(), NULL);
	if (FAILED(hr))
	{
		if (hr == E_PDB_NOT_FOUND)
		{
			printf("DIA returned E_PDB_NOT_FOUND. Check that you have internet connectivity, and the correct symbol server configured.\n");
			printf("The symbol path used was '%S'.\n", symPath.c_str());
		}
		else
		{
			printf("loadDataForExe failed for file '%ls' - HRESULT is %08X\n", exeFilename.c_str(), hr);
		}

		return false;
	}
	printf("Loading PDBs complete.\n");

	hr = (g_pDiaDataSource)->openSession(&g_pDiaSession);

	if (FAILED(hr)) 
	{
		printf("openSession failed - HRESULT is %08X\n", hr);
		return false;
	}

	g_pDiaSession->put_loadAddress(0x0);

	hr = (g_pDiaSession)->get_globalScope(&g_pGlobalSymbol);

	if (hr != S_OK) 
	{
		printf("get_globalScope failed\n");
		return false;
	}

	// Now we can resolve the symbols we want.
	unsigned long long MmPFNDatabase = findSymbol(g_pGlobalSymbol, L"MmPfnDatabase");
	unsigned long long ExAllocatePoolWithTag = findSymbol(g_pGlobalSymbol, L"ExAllocatePoolWithTag");

	if (MmPFNDatabase == 0)
		printf("Unable to resolve MmPFNDatabase");
	if (ExAllocatePoolWithTag == 0)
		printf("Unable to resolve ExAllocatePoolWithTag");
	if (MmPFNDatabase == 0 || ExAllocatePoolWithTag == 0)
		return false;

	return ExAllocatePoolWithTag - MmPFNDatabase;
}

unsigned long findSymbol(IDiaSymbol* g_pGlobalSymbol, const wchar_t* symbolName)
{
	IDiaEnumSymbols *pEnumSymbols;

	if (FAILED(g_pGlobalSymbol->findChildren(SymTagPublicSymbol, symbolName, nsNone, &pEnumSymbols)))
		return false;

	IDiaSymbol *pCompiland;
	unsigned long celt;

	if (FAILED(pEnumSymbols->Next(1, &pCompiland, &celt)) || (celt != 1))
		return false;

	unsigned long symRVA;
	pCompiland->get_relativeVirtualAddress(&symRVA);

	pCompiland->Release();
	pEnumSymbols->Release();

	return symRVA;
}