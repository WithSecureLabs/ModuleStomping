#pragma once
#include "moduleManipulation.h"

BOOL EnableDebugPrivilege(BOOL bEnable);
void* injectLoadLibrary(HANDLE toScanHandle, const wchar_t* toLoad);
unsigned char* getModuleBase(HANDLE toScanHandle, const wchar_t* moduleNameSubstring);
BOOL isModuleLoaded(HANDLE toScanHandle, const wchar_t* moduleNameSubstring);
DWORD getPIDForProcessByName(TCHAR* toFind);
