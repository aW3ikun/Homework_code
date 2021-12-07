#pragma once
#include<Windows.h>
#include<stdio.h>
#include<assert.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DLL_QUERY_HMODULE		6

//�滻������  
#ifdef _DEBUG  
#define DEBUG_INFO(format, ...) printf("Function:%s\n%s\n", __FUNCTION__,format);
#define DEBUG_ERROR(format)  printf("File:%s, Line:%d, Function:%s\n%s\tError_Code: %d\n", __FILE__, __LINE__, __FUNCTION__,format,GetLastError( ));
//#define DEBUG_INFO(format, ...) NULL;
#else  
//#define DEBUG_INFO(format, ...) printf("%s\n",format);
#define DEBUG_INFO(format, ...) NULL
#define DEBUG_ERROR(format) NULL;

#endif  

typedef ULONG_PTR (WINAPI* REFLECTIVELOADER)( VOID );
typedef BOOL (WINAPI* DLLMAIN)( HINSTANCE, DWORD, LPVOID );


extern LONGLONG LongFileSize;
//���PE�Ͱ汾
BOOL checkPeAndBit(PIMAGE_DOS_HEADER pDosHeader);

//��Ҫ�ӿڵ���
BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//��80�ֽڿռ����������,��һ�������������
BOOL AddOneSectionNormal(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//��PEͷ��ǰ
BOOL	AddSectionAdvanceNtHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//����һ���� ���һ����
BOOL	ExpandSection(DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//����һ���ڣ�����Ӷ���ĵ����
BOOL	ExpandSectionToAddImportTable(PCHAR pFileName, PCHAR pDllName, PCHAR pFuncName);

//�ϲ���һ����
BOOL	MergeOneSection(PCHAR pFileName);

//�ļ�����
//���ļ�
PBYTE	MyReadFile(PCHAR pFileName, PDWORD pFileSize,DWORD dwSectionSize);
//ʹ�ö�Heap��ȡ�ļ�
LPVOID	HeapReadFile(PCHAR pFileName);
//д�ļ�
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD FileSize,  PCHAR pFileName);
//�������ݵ��ļ�ĩβ
VOID	MyCopyBufferToFileEnd(PBYTE	pFileBuffer, DWORD	dwSectionSize,DWORD dwFileSize, PBYTE pCode);
////��ȡ�ļ���С
//ULONG_PTR MyGetFileSize(HANDLE hFile);

//�����ļ���
PCHAR AddFileName(PCHAR pFileName);


//ΪOpenProcess����Ȩ�� 
//��SeDebugPrivilege����ʾ����Ȩ�����ڵ��Լ������������̵��ڴ�
BOOL AdvancePrivilege2Debug( );


//��ȡ����ע��ĺ�����ַ�����е���
HANDLE	WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter, PCHAR pFuncName);

//�򿪽��� ����Զ���߳�
//����ע��ӿ�
//����ID��DLL���ݣ�DLL��С������������������
VOID InjectDLL(DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength, PCHAR pFuncName, LPVOID lpParameter,BOOL bFlag);

//����DLL ��ȡDLL�ľ��
HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength, PCHAR pFuncName);
