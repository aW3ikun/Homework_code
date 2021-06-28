#pragma once

#define BUFSIZE 512
#include<process.h>
#include<Windows.h>
#include<cstdio>
#include<stdlib.h>
#include<winhttp.h>
//#include<WinSock2.h>
#include"detours/detours.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"detours\\detourslib_X86\\detours.lib")
#pragma comment(lib,"detours\\detourslib_X64\\detours.lib")


#pragma comment(linker, "/INCLUDE:__tls_used")
static __declspec(thread) TCHAR lpMessage[BUFSIZE] = { 0 };
static int (WINAPI* OldConnect)(
	SOCKET s,
	const sockaddr* name,
	int namelen
	);
VOID Hook();
VOID UnHook();

unsigned int WINAPI ThreadProc(LPVOID pParam);
BOOL Log(LPWSTR lpszStr);
int WINAPI NewConnect(
	SOCKET s,
	const sockaddr* name,
	int namelen
);

void NewInternetOpenUrl(
	HINTERNET hInternet,
	LPCSTR    lpszUrl,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
);

void NewHttpOpenRequestA(
	HINTERNET hConnect,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR* lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
);
BOOL NewCreateProcessA(
	LPCSTR                lpApplicationName,
	LPSTR                 lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL                  bInheritHandles,
	DWORD                 dwCreationFlags,
	LPVOID                lpEnvironment,
	LPCSTR                lpCurrentDirectory,
	LPSTARTUPINFOA        lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
);
HMODULE  WINAPI MyLoadLibraryExw(LPCWSTR lpLibFileName, HANDLE  hFile, DWORD   dwFlags);