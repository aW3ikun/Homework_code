// Pipe_Server.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>
#include<cstdio>
#include<process.h>

#define BUFSIZE 1024  

unsigned int WINAPI InstanceThread(PVOID pParam);


int main()
{
	BOOL fConnected = 0;
	DWORD  dwThreadId = 0;
	HANDLE hPipe, hThread;
	LPTSTR lpszPipeName = (LPTSTR)L"\\\\.\\pipe\\detourspipe";

	while (TRUE) {
		hPipe = CreateNamedPipe(
			lpszPipeName,
			PIPE_ACCESS_INBOUND,
			PIPE_TYPE_MESSAGE |
			PIPE_READMODE_MESSAGE |
			PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			BUFSIZE,
			BUFSIZE,
			0,
			NULL
		);
		if (hPipe == INVALID_HANDLE_VALUE) {
			printf("CreatePipe failed");
			return 0;
		}

		fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
		if (fConnected) {
			hThread = (HANDLE)_beginthreadex(
				NULL,
				0,
				InstanceThread,
				(VOID *)hPipe,
				0,
				NULL
			);
			if (hThread == NULL) {
				printf("CreateThread failed");
			}
			else {
				CloseHandle(hThread);
			}
		}
		else {
			CloseHandle(hPipe);
		}
	}
	return 0;
	system("pause");

}
unsigned int WINAPI InstanceThread(PVOID pParam) {
	HANDLE hPipe = (HANDLE)pParam;
	TCHAR chRequest[BUFSIZE];
	DWORD cbBytesRead;

	while (TRUE) {
		BOOL fSuccess = ReadFile(
			hPipe,
			chRequest,
			BUFSIZE * sizeof(TCHAR),
			&cbBytesRead,
			NULL
		);
		if (!fSuccess || cbBytesRead == 0)
			break;

		wprintf(TEXT("%s\r\n"),(const wchar_t*)chRequest);
	}
	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	_endthreadex(0);
	return 0;
}
