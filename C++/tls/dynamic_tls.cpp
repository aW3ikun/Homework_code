#include<cstdio>
#include<windows.h>

#pragma comment(linker, "/INCLUDE:__tls_used")

DWORD g_tlsIndex;

DWORD WINAPI WorkThread(LPVOID param)
{
	TlsSetValue(g_tlsIndex, 0);

	for (size_t i = 0; i < 10; i++)
	{
		Sleep(1);
		int n = (int)TlsGetValue(g_tlsIndex);
		printf("ThreadId=%d num=%d\n", GetCurrentThreadId(), n);
		TlsSetValue(g_tlsIndex, (LPVOID)++n);

	}
	return 0;
}

#define thread_num 3
int main(int argc, char* argv[]) {
	g_tlsIndex = TlsAlloc();
	if (g_tlsIndex != TLS_OUT_OF_INDEXES){
		HANDLE hThread[thread_num];
		for (int i = 0; i < thread_num; i++) {
			hThread[i] = CreateThread(NULL, 0, WorkThread, NULL, 0, NULL);
		}
		WaitForMultipleObjects(thread_num, hThread, TRUE, 60 * 10000);
		printf("%d", g_tlsIndex);

	}
	else {
		printf("TlsAlloc error\n");
	}
	TlsFree(g_tlsIndex);

	system("pause");
}