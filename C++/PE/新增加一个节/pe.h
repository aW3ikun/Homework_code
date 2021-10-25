#pragma once
#include"_global.h"

//ָ��SectionTable��ĩβ
extern  PBYTE pZero ;


//�ж�PE�ļ�
BOOL	IsPE(PIMAGE_DOS_HEADER pDosHeader);

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

typedef struct  {
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
}PEALIGNMENT,*PPEALIGNMENT;
//��ȡ�ڴ������ļ�����
VOID GetAlignment(PIMAGE_DOS_HEADER	pDosHeader, PPEALIGNMENT pPeAlignment);

//��ȡ�ڱ���
DWORD	GetNumberOfSection(PIMAGE_DOS_HEADER	pDosHeader);

//��ȡ�ڼ����ڱ�
PIMAGE_SECTION_HEADER	GetXXSectionHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial);

//�жϽ����ռ��Ƿ����ռ� >=0x50
BOOL	JudgeSize(PIMAGE_DOS_HEADER	pDosHeader);

//����NumberOfSections
VOID SetNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	AddSectionNum);
//����SizeOfImage
BOOL SetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);
//����e_lfanew
VOID SetElfanew(PIMAGE_DOS_HEADER pDosHeader, LONG dwElfanew);
//����һ���ڵ�ϰ�ߣ��޸����һ���ڱ��SizeOfRawData �� VirtualSize
VOID SetLastSectionRawDataAndVirtualSize(PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD dwSectionSize);

//���������
VOID AddSectionAttribute(PIMAGE_SECTION_HEADER pLastSectionHeader, INT Add);

//�������PointerToRawData��VirtualAddress
BOOL	CalcSectionTableAddress(PIMAGE_DOS_HEADER pDosHeader, PDWORD dwStartVirtualAddress, PDWORD dwStartFileAddress);

//��չ�ڴ�
PBYTE	StretchFile(PIMAGE_DOS_HEADER pDosHeader) {
	//������� Ӳ�����ļ���ӳ��
	PBYTE	pFile = NULL;
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	DWORD	dwSizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;
	DWORD	dwNumberOfSection = GetNumberOfSection(pDosHeader);

	pFile = VirtualAlloc(NULL, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	
	if (pFile != NULL) {
		DEBUG_INFO("[-]����ռ�ʧ��\n");
		return NULL;
	}

	//��������PEͷ
	Copy

	//��������

	return pFile;
	
}