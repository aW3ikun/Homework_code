#pragma once
#include"_global.h"
//ָ��SectionTable��ĩβ
extern  PBYTE pZero ;

//��ȡNtHeader
PIMAGE_NT_HEADERS GetNtHeader(PIMAGE_DOS_HEADER pDosHeader);

//��ȡNtHeaders��С
DWORD	GetSizeOfNtHeaders();

//��ȡSectionTable��С
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

//�жϽ����ռ��Ƿ����ռ� >=0x50
BOOL	JudgeSize(PIMAGE_DOS_HEADER	pDosHeader);

//����NumberOfSections
VOID SetNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	AddSectionNum);
//����SizeOfImage
VOID SetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);
//����e_lfanew
VOID SetElfanew(PIMAGE_DOS_HEADER pDosHeader, LONG dwElfanew);

//�������PointerToRawData��VirtualAddress
BOOL	CalcSectionTableAddress(PIMAGE_DOS_HEADER pDosHeader, PDWORD dwStartVirtualAddress, PDWORD dwStartFileAddress);