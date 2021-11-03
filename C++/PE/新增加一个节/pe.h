#pragma once
#include"_global.h"

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
PIMAGE_NT_HEADERS GetNtHeader(PIMAGE_DOS_HEADER pDosHeader);

//��ȡNtHeaders��С
DWORD	GetSizeOfNtHeaders();
//��ȡSectionTable��С = ����SectionHeader������
DWORD GetSizeOfSectionTable(PIMAGE_DOS_HEADER pDosHeader);
//��ȡSectionHeader��С
DWORD GetSizeOfSectionHeader();
//��ȡDOS+DOS_Stub
DWORD	GetSizeOfDosAndStub(PIMAGE_DOS_HEADER pDosHeader);
//��ȡDosͷ��С
DWORD	GetSizeOfDos();
//ȡģ�жϴ�С
DWORD	GetStartAddress(DWORD	dwAlignment, DWORD	dwSize, DWORD	dwAddress);
//��ȡ�����С
DWORD GetAlign(DWORD	dwAlignment, DWORD	dwSize);

typedef struct {
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
}PEALIGNMENT, * PPEALIGNMENT;
//��ȡ�ڴ������ļ�����
VOID GetAlignment(PIMAGE_DOS_HEADER	pDosHeader, PPEALIGNMENT pPeAlignment);

//��ȡ�ڱ���
DWORD	GetNumberOfSection(PIMAGE_DOS_HEADER	pDosHeader);
//��ȡ�ڼ����ڱ�
PIMAGE_SECTION_HEADER	GetXXSectionHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial);
//��ȡ�ڱ�����
INT GetSectionCharacteristics(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial);

//��ȡ�ϲ��ĺ�����δ�С
DWORD	GetAllSizeOfSection(PIMAGE_DOS_HEADER pDosHeader);

//��ȡ�ض�IMAGE_DATA_DIRECTORY��RVA
ULONG_PTR GetDataDirectoryRVA(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry);
//��ȡ�ض�IMAGE_DATA_DIRECTORY��Size
ULONG_PTR GetDataDirectorySize(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectorySize);
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