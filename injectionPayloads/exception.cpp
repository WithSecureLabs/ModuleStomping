#include <windows.h>

__declspec(dllexport) void payload()
{
	bool didCatch = FALSE;
  try
	{
		throw 1;
	}
	catch(int)
	{
		didCatch = TRUE;
	}
	if (!didCatch)
		MessageBoxA(0, "No exception caught", "Results", 0);
	else
		MessageBoxA(0, "Exception caught OK", "Results", 0);
	ExitThread(0);
}
BOOL WINAPI DllMain( _In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved )
{
	return 1;
}