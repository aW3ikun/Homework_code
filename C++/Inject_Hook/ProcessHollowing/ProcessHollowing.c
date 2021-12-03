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
		//��������Ľ���
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
			DEBUG_ERROR("[-]����ʧ��");
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

		//�����㹻�Ŀռ�
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