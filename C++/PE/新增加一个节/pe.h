#pragma once
#include"_global.h"

//指向SectionTable的末尾
extern  PBYTE pZero ;


//判断PE文件
BOOL	IsPE(PIMAGE_DOS_HEADER pDosHeader);

//获取NtHeader
PIMAGE_NT_HEADERS GetNtHeader(PIMAGE_DOS_HEADER pDosHeader);

//获取NtHeaders大小
DWORD	GetSizeOfNtHeaders();

//获取SectionTable大小 = 所有SectionHeader加起来
DWORD GetSizeOfSectionTable(PIMAGE_DOS_HEADER pDosHeader);

//获取SectionHeader大小
DWORD GetSizeOfSectionHeader();

//获取DOS+DOS_Stub
DWORD	GetSizeOfDosAndStub(PIMAGE_DOS_HEADER pDosHeader);

//获取Dos头大小
DWORD	GetSizeOfDos();

//取模判断大小
DWORD	GetStartAddress(DWORD	dwAlignment, DWORD	dwSize, DWORD	dwAddress);

typedef struct  {
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
}PEALIGNMENT,*PPEALIGNMENT;
//获取内存对齐和文件对齐
VOID GetAlignment(PIMAGE_DOS_HEADER	pDosHeader, PPEALIGNMENT pPeAlignment);

//获取节表数
DWORD	GetNumberOfSection(PIMAGE_DOS_HEADER	pDosHeader);

//获取第几个节表
PIMAGE_SECTION_HEADER	GetXXSectionHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial);

//判断节区空间是否空余空间 >=0x50
BOOL	JudgeSize(PIMAGE_DOS_HEADER	pDosHeader);

//设置NumberOfSections
VOID SetNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	AddSectionNum);
//设置SizeOfImage
BOOL SetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);
//设置e_lfanew
VOID SetElfanew(PIMAGE_DOS_HEADER pDosHeader, LONG dwElfanew);
//扩大一个节的习惯，修改最后一个节表的SizeOfRawData 和 VirtualSize
VOID SetLastSectionRawDataAndVirtualSize(PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD dwSectionSize);

//定义节属性
VOID AddSectionAttribute(PIMAGE_SECTION_HEADER pLastSectionHeader, INT Add);

//计算添加PointerToRawData和VirtualAddress
BOOL	CalcSectionTableAddress(PIMAGE_DOS_HEADER pDosHeader, PDWORD dwStartVirtualAddress, PDWORD dwStartFileAddress);

//扩展内存
PBYTE	StretchFile(PIMAGE_DOS_HEADER pDosHeader) {
	//传入的是 硬盘中文件的映射
	PBYTE	pFile = NULL;
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	DWORD	dwSizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;
	DWORD	dwNumberOfSection = GetNumberOfSection(pDosHeader);

	pFile = VirtualAlloc(NULL, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	
	if (pFile != NULL) {
		DEBUG_INFO("[-]申请空间失败\n");
		return NULL;
	}

	//拷贝整个PE头
	Copy

	//拷贝区块

	return pFile;
	
}