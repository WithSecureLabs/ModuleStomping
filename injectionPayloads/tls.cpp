#include <windows.h>

__thread unsigned int TLSGlobal = 0;
bool failed;
void threadEntry()
{
	unsigned int localVar = 0;

	for(unsigned int n=0; n<10000000; n++)
	{
		TLSGlobal++;
		localVar++;
	}
	
	if (localVar != TLSGlobal)
		failed = TRUE;
}

__declspec(dllexport) void payload()
{
	failed = FALSE;

	DWORD threadIDs[10];
	HANDLE threadHandles[10];

	for(unsigned int n=0; n<10; n++)
		threadHandles[n] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadEntry, 0, 0, &threadIDs[n]);

	for(unsigned int n=0; n<10; n++)
		WaitForSingleObject(threadHandles[n], INFINITE);

	if (failed)
		MessageBoxA(0, "Incorrect", "Results", 0);
	else
		MessageBoxA(0, "Correct", "Results", 0);
}

int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	payload();
	return 0;
}
