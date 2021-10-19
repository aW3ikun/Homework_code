// Pipe_Client.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <cstdio>
#include <Windows.h>

#define BUFSIZE 512
int main()
{
	HMODULE hLib = LoadLibrary(L"Detours_Dll.dll");
	const TCHAR lpszPipename[] = L"\\\\.\\pipe\\detourspipe";
	HANDLE hPipe;
	DWORD dwMode, cbToWrite, fSuccess;
	while (1)
	{
		hPipe = CreateFile(
			lpszPipename,   // pipe name
			GENERIC_WRITE,
			0,              // no sharing 
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe 
			0,              // default attributes 
			NULL);          // no template file 

	  // Break if the pipe handle is valid. 

		if (hPipe != INVALID_HANDLE_VALUE)
			break;

		// Exit if an error other than ERROR_PIPE_BUSY occurs. 

		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			printf("Could not open pipe. GLE=%d\n", GetLastError());
			return -1;
		}

		// All pipe instances are busy, so wait for 20 seconds. 

		if (!WaitNamedPipe(lpszPipename, 20000))
		{
			printf("Could not open pipe: 20 second wait timed out.");
			return -1;
		}
	}

	// The pipe connected; change to message-read mode. 

	dwMode = PIPE_READMODE_MESSAGE;
	fSuccess = SetNamedPipeHandleState(
		hPipe,    // pipe handle 
		&dwMode,  // new pipe mode 
		NULL,     // don't set maximum bytes 
		NULL);    // don't set maximum time 
	if (!fSuccess)
	{
		printf("SetNamedPipeHandleState failed. GLE=%d\n", GetLastError());
		return -1;
	}
	while(1){
		// Send a message to the pipe server. 
		TCHAR  lpvMessage[BUFSIZE] = { 0 };
		DWORD cbWritten = 0;
		//GetModuleFileName(NULL, lpvMessage, BUFSIZE);
		wscanf_s(L"%s", lpvMessage, (unsigned)_countof(lpvMessage));
		cbToWrite = (lstrlen(lpvMessage) + 1) * sizeof(TCHAR);
		//TCHAR lpszStr[BUFSIZE] = { 0 };


		fSuccess = WriteFile(
			hPipe,                  // pipe handle 
			lpvMessage,             // message 
			cbToWrite,              // message length 
			&cbWritten,             // bytes written 
			NULL);                  // not overlapped 

		if (!fSuccess)
		{
			printf("WriteFile to pipe failed. GLE=%d\n", GetLastError());
			return -1;
		}
	}


	system("pause");

	CloseHandle(hPipe);
	FreeLibrary(hLib);
	return 0;
}

