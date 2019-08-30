
#include <windows.h>

__declspec(dllexport) void payload()
{
	MessageBoxA(0, "hi", "Hello world", 0);
	ExitThread(0);
}
BOOL WINAPI DllMain( _In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved )
{
	return 1;
}