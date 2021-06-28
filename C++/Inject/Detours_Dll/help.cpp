#include"help.h"

static HMODULE(WINAPI* PFnLoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE  hFile, DWORD   dwFlags) = (HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD))DetourFindFunction("KernelBase.dll", "LoadLibraryExW");
HMODULE  WINAPI MyLoadLibraryExw(LPCWSTR lpLibFileName, HANDLE  hFile, DWORD   dwFlags)
{
	TCHAR lpszStr[BUFSIZE] = { 0 };
	wsprintf(lpszStr, L"[+]LoadLibrary %s \n", lpLibFileName);
	Log(lpszStr);
	return PFnLoadLibraryExW(lpLibFileName, hFile, dwFlags); //调用原函数,就是不做处理

}
VOID Hook() {
	//OldConnect = (int(WINAPI*)(SOCKET s,
	//	const sockaddr * name,
	//	int namelen))DetourFindFunction("ws2_32.dll", "connect");
	
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)PFnLoadLibraryExW, MyLoadLibraryExw);
	if (DetourTransactionCommit() == NO_ERROR)
	{
		TCHAR lpszStr[BUFSIZE] = { 0 };
		wsprintf(lpszStr, L"[+]Hook Success! 0x%x \n", PFnLoadLibraryExW);
		Log(lpszStr);
	}

}
VOID UnHook() {
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)OldConnect, NewConnect);
	DetourTransactionCommit();
}

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

int WINAPI NewConnect(
	SOCKET s,
	const sockaddr* name,
	int namelen
) {
	size_t converted = 0;
	sockaddr_in* pV4Addr = (struct sockaddr_in*)&name;
	char *ip = inet_ntoa(pV4Addr->sin_addr);
	int len = strlen(ip) + 1;
	TCHAR* lpIp = new wchar_t[len];
	mbstowcs_s(&converted, lpIp,len,ip, _TRUNCATE);

	TCHAR lpMessage[BUFSIZE] = { 0 };
	wsprintf(lpMessage,L"[+]connect to %s \r\n",lpIp);
	Log(lpMessage);
	delete[] lpIp;
	return connect(s, name, namelen);
}
void NewInternetOpenUrl(
	HINTERNET hInternet,
	LPCSTR    lpszUrl,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
) {

}

void NewHttpOpenRequestA(
	HINTERNET hConnect,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR* lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
) {

}