#include"pch.h"
#include"help.h"
#include<Windows.h>


BOOL InjectLib(INT dwProcessId, PTSTR szLibFile) {
	BOOL bOk = FALSE;
	HANDLE hProcess = NULL, hThread = NULL;
	PWSTR pszLibFileRemote = NULL;
	__try {
		hProcess = OpenProcess(
			PROCESS_ALL_ACCESS,
			FALSE, dwProcessId
		);
		if (hProcess == NULL) __leave;
		int cch = lstrlen(szLibFile) + 1;
		int cb = cch * sizeof(wchar_t);

		pszLibFileRemote = (PWSTR)
			VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
		if (pszLibFileRemote == NULL) __leave;
		
		if (!WriteProcessMemory(hProcess, pszLibFileRemote, (LPVOID)szLibFile, cb, NULL)) {
			int a = GetLastError();
			LPSTR str = NULL;
			wsprintfA(str, "%s", NULL, MB_OK);
			MessageBoxA(NULL, str, NULL, MB_OK);
			__leave;
		}


		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRtn == NULL) __leave;
		hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
		int a = GetLastError();
		if (hThread == 0) __leave;
		WaitForSingleObject(hThread, INFINITE);
		bOk= TRUE;

	}
	__finally {
		if (pszLibFileRemote != NULL)
			VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
		if (hThread != NULL)
			CloseHandle(hThread);
		if (hProcess != NULL)
			CloseHandle(hProcess);
	}
	return bOk;
}


BOOL FreeLib(INT dwProcessId, PTSTR szLibFile) {
	BOOL bOk = FALSE;
	HANDLE hProcess = NULL, hThread = NULL;
	PWSTR pszLibFileRemote = NULL;
	__try {
		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION |
			PROCESS_CREATE_THREAD |
			PROCESS_VM_OPERATION,
			FALSE, dwProcessId
		);
		if (hProcess == NULL) __leave;
		int cch = lstrlen(szLibFile) + 1;
		int cb = cch * sizeof(wchar_t);

		pszLibFileRemote = (PWSTR)
			VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
		if (pszLibFileRemote == NULL) __leave;

		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "FreeLibrary");
		if (pfnThreadRtn == NULL) __leave;
		hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
		if (hThread == 0) __leave;
		WaitForSingleObject(hThread, INFINITE);
		bOk = TRUE;

	}
	__finally {
		if (pszLibFileRemote != NULL)
			VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
		if (hThread != NULL)
			CloseHandle(hThread);
		if (hProcess != NULL)
			CloseHandle(hProcess);
	}
	return bOk;
}
