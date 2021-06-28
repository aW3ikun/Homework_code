// dllmain.cpp : 定义 DLL 应用程序的入口点。
#define BUFSIZE 512

#include<Windows.h>
#include<iostream>
#include<process.h>
#include"detours/detours.h"

#pragma comment(lib,"detours\\detourslib_X86\\detours.lib")
#pragma comment(linker, "/INCLUDE:__tls_used")

__declspec(thread) TCHAR lpszStr[BUFSIZE] = { 0 };


unsigned int WINAPI ThreadProc(LPVOID pParam);
BOOL NewThread(LPWSTR lpszStr);

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {
		MessageBox(NULL, L"Inject Success", NULL, MB_OK);
		if (GetModuleFileNameW(NULL, lpszStr, BUFSIZE)) {
			NewThread(lpszStr);
		}
	}

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH: {
		;
	}
						   break;
	}
	return TRUE;
}


BOOL NewThread(LPWSTR lpszStr) {
	HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, ThreadProc, (VOID*)lpszStr, 0, NULL);
	if (hThread) {
		CloseHandle(hThread);
		return TRUE;
	}
	return FALSE;
}
unsigned int WINAPI ThreadProc(LPVOID pParam) {
	LPTSTR lpszPipeName = (LPTSTR)L"\\\\.\\pipe\\detourspipe";
	HANDLE hPipe;
	while (TRUE) {
		hPipe = CreateFile(
			lpszPipeName,
			GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE)
			break;
		if (GetLastError() != ERROR_PIPE_BUSY) {
			MessageBox(NULL, L"Could not open pipe", NULL, MB_OK);
			return 0;
		}
		if (!WaitNamedPipe(lpszPipeName, 200000)) {
			MessageBox(NULL, L"Could not open pipe", NULL, MB_OK);
			return 0;
		}
	}
	DWORD dwMode = PIPE_READMODE_MESSAGE;
	DWORD fSuccess = SetNamedPipeHandleState(
		hPipe,
		&dwMode,
		NULL,
		NULL
	);
	LPWSTR lpMessage = (LPWSTR)pParam;
	DWORD cbWritten = 0;
	fSuccess = WriteFile(hPipe, lpMessage, (lstrlen(lpMessage) + 1) * sizeof(TCHAR), &cbWritten, NULL);
	if (!fSuccess) {
		MessageBox(NULL, L"WriteFile Failed", NULL, MB_OK);
		CloseHandle(hPipe);
		return -1;
	}
	CloseHandle(hPipe);
	_endthreadex(0);
	return 0;
}
