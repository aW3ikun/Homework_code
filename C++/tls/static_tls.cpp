#include<stdint.h>
#include<cstdio>
#include<windows.h>

#pragma comment(linker, "/INCLUDE:__tls_used")

__declspec(thread) uint32_t num = 0;

DWORD WINAPI WorkThread(LPVOID param)
{
	Sleep(1);
	for (size_t i = 0; i < 10; i++)
	{
		printf("PID=%d g_dwNumber=%d\n", GetCurrentThreadId(), num++);
	}
	return 0;
}


int main(int argc, char* argv[]) {
	printf("main start\n");
	HANDLE hThread[3];
	for (int i = 0; i < 3; i++) {
		hThread[i] = CreateThread(NULL, 0, WorkThread, NULL, 0, NULL);
	}
	WaitForMultipleObjects(3, hThread, TRUE,60 * 1000);
	
	printf("main end\n");
	system("pause");
}