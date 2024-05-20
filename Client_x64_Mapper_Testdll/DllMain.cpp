#include <Windows.h>


typedef struct {
	bool isExecuted;
	char msg[32];
}TEST_DATA, *PTEST_DATA;

//Test imports
void test() {
	MessageBoxA(NULL, "Hello from Testdll", "Testdll", MB_OK);
}

void initTestData(PTEST_DATA pData) {
	pData->isExecuted = true;
	strcpy_s(pData->msg, "Hello from Testdll");
	test();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		initTestData((PTEST_DATA)lpReserved);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}