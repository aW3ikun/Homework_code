#include"pch.h"
#include"help.h"
#include<Windows.h>
#include "tlhelp32.h"


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
			__leave;
		}


		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRtn == NULL) __leave;
		hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
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
			PROCESS_ALL_ACCESS,
			FALSE, dwProcessId
		);
		BOOL bMore = FALSE, bFound = FALSE;
		HANDLE hSnapshot, hThread;
		HMODULE hModule = NULL;
		MODULEENTRY32 me = { sizeof(me) };
		LPTHREAD_START_ROUTINE pThreadProc;

		// dwPID = notepad ����ID
		// ʹ��TH32CS_SNAPMODULE��������ȡ���ص�notepad���̵�DLL����
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		bMore = Module32First(hSnapshot, &me);
		for (; bMore; bMore = Module32Next(hSnapshot, &me))
		{
			if (!_tcsicmp((LPCTSTR)me.szModule, szLibFile) ||
				!_tcsicmp((LPCTSTR)me.szExePath, szLibFile))
			{
				bFound = TRUE;
				break;
			}
		}
		if (!bFound)
		{
			CloseHandle(hSnapshot);
			__leave;
		}

		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "FreeLibrary");
		if (pfnThreadRtn == NULL) __leave;
		hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, me.hModule, 0, NULL);
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
