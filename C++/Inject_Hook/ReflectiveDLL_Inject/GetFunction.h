#ifndef _GETFUNCTION_H_
#define _GETFUNCTION_H_
//ʹ��GetFunction.h GetFunction.c 
//ʹ��GetFunction������ȡ������ַ
//#include<Windows.h>
#include"../../PE/������һ����/pe.h"

#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54

#define HASH_KEY						13

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)

typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LOADLIBRARY)(LPCWSTR);

typedef ULONG   PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _UNICODE_STR {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STR, * PUNICODE_STR;

//https://docs.microsoft.com/zh-cn/windows/win32/api/winternl/ns-winternl-peb_ldr_data?redirectedfrom=MSDN
typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

//windbg> dt _LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY {
	//ֱ�Ӳ�ʹ�õ�һ���ֶΣ��������
	//LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	//������·����  _UNICODE_STRING "C:\Windows\SYSTEM32\ntdll.dll"
	UNICODE_STR FullDllName;
	//_UNICODE_STRING "ntdll.dll"
	UNICODE_STR BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STR ImagePathName;
	UNICODE_STR CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

//���Ƽ���
#pragma intrinsic(_rotr)
__forceinline DWORD ror(DWORD d);

//���㺯����hash
__forceinline DWORD hash(DWORD d);

//��ȡ�ض�������ַ
ULONG_PTR GetFunction(DWORD dwDllHash, DWORD dwFuncHashz);

//��ȡpeb��ַ
ULONG_PTR GetPeb();

//��ȡLdr��ַ
ULONG_PTR GetLdr(ULONG_PTR uiPebAddr);

//ȫ��תΪСд��Ȼ��hash����
VOID ComputeHash(ULONG_PTR	uiDllName, ULONG_PTR	uiDllLength, PDWORD	uiDllHash);

#endif