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

void CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile)
{
	DEBUG_INFO("[+]Creating Process\r\n");

	BOOL bResult = FALSE;
	STARTUPINFOA StartupInfo = { 0 };
	PROCESS_INFORMATION ProcessInformation = { 0 };

	CONTEXT context = { 0 };
	ULONG_PTR ulImageBase = 0;
	DWORD dwFileSize = 0;

	//memory of source file 
	LPVOID lpSourceFile = NULL;

	StartupInfo.cb = sizeof(StartupInfo);
	do 
	{
		//创建挂起的进程
		if ( !CreateProcessA(
			0,
			pDestCmdLine,
			0,
			0,
			0,
			CREATE_SUSPENDED,
			0,
			0,
			&StartupInfo,
			&ProcessInformation
		) ) {
			DEBUG_ERROR("[-]创建失败");
			break;
		}

		FARPROC pfnZwUnmapViewOfSecrtion = GetProcAddress(LoadLibraryA("ntdll.dll"), "ZwNtUnMapViewOfSection");
		_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)pfnZwUnmapViewOfSecrtion;

		//Get ImageBase
		//x86 peb+0x8 / x64 peb+0x10
		GetThreadContext(ProcessInformation.hThread, &context);
		
		ReadProcessMemory(ProcessInformation.hProcess,
#ifdef _WIN64
		(LPVOID)( context.Rbx + 0x10 ),
#else
		(LPVOID)( context.Ebx + 0x8 ),
#endif
			& ulImageBase, sizeof(ULONG_PTR), NULL);

		//unmap image
		NtUnmapViewOfSection(ProcessInformation.hProcess, (PVOID)ulImageBase);

		//ReadFile
		lpSourceFile =  MyReadFile(pSourceFile, &dwFileSize, 0);

		//申请足够的空间
		getsizeofimagfe


	} while (0);


	//avoid leak process handle
	CloseHandle(ProcessInformation.hProcess);
	CloseHandle(ProcessInformation.hThread);
}

int main(int argc, char* argv[])
{

	CreateHollowedProcess("calc","HelloWorld.exe");

	return	0;
}