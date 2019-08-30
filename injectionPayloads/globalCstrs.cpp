#include <windows.h>

class foo
{
public:
	foo(int num)
	{
		this->num = num * 2;
	}
	int num;
};

foo myfoo(10);

__declspec(dllexport) void payload()
{
	if (myfoo.num != 20)
		MessageBoxA(0, "Incorrect", "Results", 0);
	else
		MessageBoxA(0, "Correct", "Results", 0);
}
