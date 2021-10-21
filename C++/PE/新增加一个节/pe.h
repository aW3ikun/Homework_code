#pragma once
#include"_global.h"
//ָ��SectionTable��ĩβ
extern  PBYTE pZero ;

//��ȡNtHeader
PIMAGE_NT_HEADERS GetNtHeader(PIMAGE_DOS_HEADER pDosHeader);

//��ȡNtHeaders��С
DWORD	GetSizeOfNtHeaders();

//��ȡSectionTable��С
DWORD GetSizeOfSectionTable(PIMAGE_NT_HEADERS pNtHeader);


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

//ȡģ�жϴ�С
DWORD	GetStartAddress(DWORD	dwAlignment, DWORD	dwSize, DWORD	dwAddress);