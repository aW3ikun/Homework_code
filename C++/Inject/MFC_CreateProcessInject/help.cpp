#include"pch.h"
#include"help.h"




DWORD GetEntryPoint(CString pszfilePath) {
	PLOADED_IMAGE ploaded_image;
	PIMAGE_NT_HEADERS pImage;
	DWORD dwEntryPoint = NULL;

	USES_CONVERSION;
	ploaded_image = ImageLoad(W2A(pszfilePath.GetString()), NULL);
	if (ploaded_image != NULL) {
		pImage = ploaded_image->FileHeader;
		dwEntryPoint = pImage->OptionalHeader.ImageBase + pImage->OptionalHeader.AddressOfEntryPoint;
		
	}
	ImageUnload(ploaded_image);
	return dwEntryPoint;
}

DWORD CreateShellCode(PROCESS_INFORMATION pi, LPVOID lpDllPath, BYTE bHeadCode[], DWORD dwBaseAddr) {
	HMODULE hK32dll = LoadLibrary(L"kernel32.dll");
	FARPROC lpLoadLibrary = GetProcAddress(hK32dll, "LoadLibraryW");
	DWORD dwAddress = (DWORD)lpLoadLibrary;
	DWORD dwResult = 0;
	ShellCode shellcode;

	LPVOID lpShellcode = VirtualAllocEx(pi.hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	memcpy(shellcode.bHeadCode, bHeadCode, 5);
	shellcode.pushad = 0x60;
	shellcode.bPush1 = 0x68;
	shellcode.dwDllPath = (DWORD)lpDllPath;
	shellcode.bMovEax = 0xbA;
	shellcode.dwLoadLibrary = dwAddress;
	shellcode.callEax = 0xd2ff;
	shellcode.bMovEsi = 0xbe;
	shellcode.dwEsiValue = (DWORD)lpShellcode+0x25;
	shellcode.bMovEdi = 0xbf;
	shellcode.dwEdiValue = dwBaseAddr;
	shellcode.bMovEcx = 0xb9;
	shellcode.dwEcxValue = 0x05;
	shellcode.wRepMovsb = 0xa4f3;
	shellcode.popad = 0x61;
	shellcode.bPush2 = 0x68;
	shellcode.dwEip = dwBaseAddr;
	shellcode.bRet = 0xc3;
	if (WriteProcessMemory(pi.hProcess, lpShellcode, &shellcode, sizeof(shellcode), NULL)) {
		dwResult = (DWORD)lpShellcode;
	}
	return dwResult;

}

BOOL Inject(CString pszfilePath, CString pszdllPath, CString& pszLog) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD old;
	BOOL bOK = FALSE;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));


	//挂起进程
	if (CreateProcess(NULL,
		(LPWSTR)pszfilePath.GetString(),
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi)) {
		CString pszProcess;
		pszProcess.Format(L"ProcessId: %d \r\n", pi.dwProcessId);
		pszLog += pszProcess.GetString();

		//EIP Hook
		BYTE bHeadCode[5] = { 0 };
		DWORD dwBaseAddr = GetEntryPoint(pszfilePath);


		if (dwBaseAddr) {
			pszLog += "[+]获取上下文成功! \r\n";
			//获取前六字节
			if (ReadProcessMemory(pi.hProcess, (LPCVOID)dwBaseAddr, bHeadCode, sizeof(bHeadCode), NULL)) {
				CString pszEip;
				pszEip.Format(L"EntryPoint: 0x%x \r\n", dwBaseAddr);
				pszLog += pszEip.GetString();
				pszLog += "[+]读取EIP成功! \r\n";

				//申请静态变量空间
				//申请shellcode空间 
				int a = pszdllPath.GetLength() + 1;
				if (LPVOID lpDllPath = VirtualAllocEx(pi.hProcess, NULL, pszdllPath.GetLength()*2 + 1, MEM_COMMIT, PAGE_READWRITE)) {
					pszLog += "[+]申请Dll路径内存成功! \r\n";
					if (WriteProcessMemory(pi.hProcess, lpDllPath, pszdllPath, pszdllPath.GetLength()*2, NULL)) {
						pszLog += "[+]写入Dll路径内存成功! \r\n";
						DWORD dwShellCode = CreateShellCode(pi, lpDllPath, bHeadCode, dwBaseAddr);
						if (dwShellCode != 0) {
							JMP jmp;
							jmp.bJmp = 0xe9;
							jmp.dwAddr = (DWORD)dwShellCode - (dwBaseAddr + 5);
							if (VirtualProtectEx(pi.hProcess, (LPVOID)dwBaseAddr, sizeof(jmp), PAGE_EXECUTE_READWRITE, &old)) {
								if (WriteProcessMemory(pi.hProcess, (LPVOID)dwBaseAddr, &jmp, sizeof(jmp), &old)) {

									bOK = TRUE;
								}
							}
						}

					}
					else {
						pszLog += "[+]写入Dll路径内存失败! \r\n";
					}

				}
				else {
					pszLog += "[-]申请Dll路径内存失败! \r\n";
				}
			}
			else {
				pszLog += "[-]读取EIP失败! \r\n";
			}
		}
		else {
			pszLog += "[-]获取上下文失败! \r\n";
		}

		ResumeThread(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return bOK;
	}
	else {
		pszLog += "[-]加载进程失败! \r\n";
		return bOK;
	}
}
