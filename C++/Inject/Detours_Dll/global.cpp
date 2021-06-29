#pragma once
#include"global.h"
BOOL Log(LPWSTR lpMessage) {
	HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, ThreadProc, (VOID*)lpMessage, 0, NULL);
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
	LPCWSTR lptemp = (LPCWSTR)pParam;
	DWORD cbWritten = 0;
	fSuccess = WriteFile(hPipe, lptemp, (lstrlen(lptemp) + 1) * sizeof(TCHAR), &cbWritten, NULL);
	if (!fSuccess) {
		MessageBox(NULL, L"WriteFile Failed", NULL, MB_OK);
		CloseHandle(hPipe);
		return -1;
	}
	CloseHandle(hPipe);
	_endthreadex(0);
	return 0;
}
