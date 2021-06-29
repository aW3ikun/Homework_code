#pragma once
#include<Windows.h>
#include<process.h>
#include"detours/detours.h"

#pragma comment(lib,"detours/detourslib_X86/detours.lib")
#define BUFSIZE 512

#pragma comment(linker, "/INCLUDE:__tls_used")
static __declspec(thread) TCHAR lpMessage[BUFSIZE] = { 0 };

typedef BOOL(WINAPI* pfnWriteFile)(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	);

unsigned int WINAPI ThreadProc(LPVOID pParam);
BOOL Log(LPWSTR lpszStr);

BOOL WINAPI  NewWriteFile(HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped);

static BOOL bHook = FALSE;
VOID SetHook();
VOID UnHook();
