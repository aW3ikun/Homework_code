#pragma once
#include"_global.h"
//指向SectionTable的末尾
extern  PBYTE pZero ;

//获取NtHeader
PIMAGE_NT_HEADERS GetNtHeader(PIMAGE_DOS_HEADER pDosHeader);

//获取NtHeaders大小
DWORD	GetSizeOfNtHeaders();

//获取SectionTable大小
DWORD GetSizeOfSectionTable(PIMAGE_NT_HEADERS pNtHeader);


typedef struct  {
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
}PEALIGNMENT,*PPEALIGNMENT;
//获取内存对齐和文件对齐
VOID GetAlignment(PIMAGE_DOS_HEADER	pDosHeader, PPEALIGNMENT pPeAlignment);

//判断节区空间是否空余空间 >=0x50
BOOL	JudgeSize(PIMAGE_DOS_HEADER	pDosHeader);

//设置NumberOfSections
VOID SetNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	AddSectionNum);
//设置SizeOfImage
VOID SetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//取模判断大小
DWORD	GetStartAddress(DWORD	dwAlignment, DWORD	dwSize, DWORD	dwAddress);