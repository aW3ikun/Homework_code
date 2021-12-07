#pragma once
#include"_global.h"

//����DllMain�������
#define	REFLECTIVELOADER_NO_PARAMETER

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_DWORD( name )*(DWORD *)(name)
#define DEREF_ULONGPTR( name )*(ULONG_PTR *)(name)
#define DEREF_WORD( name )*(WORD *)(name)

typedef FARPROC(WINAPI* GETPROCADDRESS)( HMODULE, LPCSTR );
typedef HMODULE(WINAPI* LOADLIBRARY)( LPCWSTR );
typedef VOID (WINAPI* LOAD)( VOID );

//�ض�λ�� ���ֽ� ��4λ��Type��12λ��Offset�ϳ�
typedef struct {
	WORD	offset : 12;
	WORD	type : 4;
}IMAGE_RELOC, * PIMAGE_RELOC;

//ָ��SectionTable��ĩβ
extern  PBYTE pZero;

//RVAToFileOffset
DWORD RVAToOffset(PIMAGE_DOS_HEADER pDosHeader, ULONG uRvaAddr);

//FileOffsetToRva
DWORD OffsetToRVA(PIMAGE_DOS_HEADER pDosHeader, ULONG uOffsetAddr);

//�ж�PE�ļ�
BOOL	IsPE(PIMAGE_DOS_HEADER pDosHeader);

//��ǰλ���ж�
BOOL	IsCurrentBit(PIMAGE_DOS_HEADER pDosHeader);

//��ȡNtHeader
inline PIMAGE_NT_HEADERS GetNtHeader(PIMAGE_DOS_HEADER pDosHeader);

//��ȡNtHeaders��С
DWORD	GetSizeOfNtHeaders( );
//��ȡSectionTable��С = ����SectionHeader������
DWORD GetSizeOfSectionTable(PIMAGE_DOS_HEADER pDosHeader);
//��ȡSectionHeader��С
DWORD GetSizeOfSectionHeader( );
//��ȡչ����Ĵ�С
DWORD	GetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader);
//��ȡDOS+DOS_Stub
DWORD	GetSizeOfDosAndStub(PIMAGE_DOS_HEADER pDosHeader);
//��ȡimageBase
DWORD GetImageBase(PIMAGE_DOS_HEADER pDosHeader);
//��ȡDosͷ��С
inline DWORD	GetSizeOfDos( );
//ȡģ�жϴ�С
DWORD   GetStartAddress(DWORD	dwAlignment, DWORD	dwSize, DWORD	dwAddress);
//��ȡ�����С
DWORD GetAlign(DWORD	dwAlignment, DWORD	dwSize);

typedef struct {
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
}PEALIGNMENT, * PPEALIGNMENT;
//��ȡ�ڴ������ļ�����
VOID GetAlignment(PIMAGE_DOS_HEADER	pDosHeader, PPEALIGNMENT pPeAlignment);

//��ȡ�ڱ���
inline DWORD	GetNumberOfSection(PIMAGE_DOS_HEADER	pDosHeader);
//��ȡ�ڼ����ڱ�
PIMAGE_SECTION_HEADER	GetXXSectionHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial);
//��ȡ�ڱ�����
INT GetSectionCharacteristics(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial);

//��ȡ�ϲ��ĺ�����δ�С
DWORD	GetAllSizeOfSection(PIMAGE_DOS_HEADER pDosHeader);

//��ȡ�ض�IMAGE_DATA_DIRECTORY��RVA
//IMAGE_DIRECTORY_ENTRY_XXXX
inline ULONG_PTR GetDataDirectoryRVA(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry);
//��ȡ�ض�IMAGE_DATA_DIRECTORY��Size
ULONG_PTR GetDataDirectorySize(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectorySize);
//��ȡ��ǰ��Entrypoint
ULONG_PTR GetAddressOfEntryPoint(HANDLE hProcess,PIMAGE_DOS_HEADER pDosHeader);
//�жϽ����ռ��Ƿ����ռ� >=0x50
BOOL	JudgeSize(PIMAGE_DOS_HEADER	pDosHeader);

//����NumberOfSections
VOID AddNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	AddSectionNum);
//Ϊһ�����������
VOID AddLSectionAttribute(PIMAGE_DOS_HEADER pDosHeader, DWORD Attribute, DWORD dwSerial);
//����NumberOfSections
VOID SetNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	SectionNum);
//����SizeOfImage
BOOL SetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSize);
//����e_lfanew
VOID SetElfanew(PIMAGE_DOS_HEADER pDosHeader, LONG dwElfanew);
//����һ���ڵ�ϰ�ߣ��޸����һ���ڱ��SizeOfRawData �� VirtualSize
VOID SetLastSectionRawDataAndVirtualSize(PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD dwSectionSize);
//����SizeOfRawData��VirtualSize
VOID SetSizeOfRawDataAndVirtualSize(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, DWORD dwSize);
//���õڼ����ڵ�����
VOID SetSectionCharacteristics(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, INT Characteristics);
//�����ض�IMAGE_DATA_DIRECTORY��RVA
VOID SetDataDirectoryRVA(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry, DWORD dwVirtualAddress);
//�����ض�IMAGE_DATA_DIRECTORY��Size
VOID SettDataDirectorySize(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry, DWORD dwSize);

//���������
VOID AddSectionAttribute(PIMAGE_SECTION_HEADER pLastSectionHeader, INT Add);

//�������PointerToRawData��VirtualAddress
BOOL	CalcSectionTableAddress(PIMAGE_DOS_HEADER pDosHeader, PDWORD dwStartVirtualAddress, PDWORD dwStartFileAddress);

//��չ�ڴ�
PBYTE	StretchFileToMemory(PIMAGE_DOS_HEADER pDosHeader, PDWORD pFileSize);

//��������PEͷ
VOID CopyHeader(LPVOID	pDst, PIMAGE_DOS_HEADER	pDosHeader);

//��������
BOOL CopyAllSection(LPVOID	pMemory, PIMAGE_DOS_HEADER	pFile, DWORD dwSizeOfImage);

//���������
BOOL CopyAndAddImportTable(PIMAGE_DOS_HEADER	pDosHeader, DWORD dwFileSize, DWORD dwExpandSize, PCHAR pDllName, PCHAR pFuncName);

//Shellcode �������
//��Ҫ���뺯����ַ
VOID ShellCodeRepairImportTable (
	PIMAGE_DOS_HEADER pDosHeader, GETPROCADDRESS pGetProcAddress, LOADLIBRARY pLoadLibrary);

//ShellCode�����ض�λ
VOID	ShellCodeFixReloc(PIMAGE_DOS_HEADER	pMemory, PIMAGE_DOS_HEADER pDosHeader);

//ShellCode ��Ѱδչ����������
DWORD	GetFileExportFunctionOffset(PIMAGE_DOS_HEADER	pDosHeader, PCHAR pFuncName);

//����̿���PEͷ
BOOL AcrossCopyHeader(HANDLE hProcess,LPVOID	pDst, PIMAGE_DOS_HEADER	pDosHeader);
//����̿�������
BOOL AcrossCopyAllSection (HANDLE hProcess,LPVOID	pMemory, PIMAGE_DOS_HEADER	pFile, DWORD dwSizeOfImage);