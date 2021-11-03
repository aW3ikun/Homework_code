#pragma once
#include"_global.h"

//指向SectionTable的末尾
extern  PBYTE pZero;

//RVAToFileOffset
DWORD RVAToOffset(PIMAGE_DOS_HEADER pDosHeader, ULONG uRvaAddr);

//FileOffsetToRva
DWORD OffsetToRVA(PIMAGE_DOS_HEADER pDosHeader, ULONG uOffsetAddr);

//判断PE文件
BOOL	IsPE(PIMAGE_DOS_HEADER pDosHeader);

//当前位数判断
BOOL	IsCurrentBit(PIMAGE_DOS_HEADER pDosHeader);

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
//获取对齐大小
DWORD GetAlign(DWORD	dwAlignment, DWORD	dwSize);

typedef struct {
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
}PEALIGNMENT, * PPEALIGNMENT;
//获取内存对齐和文件对齐
VOID GetAlignment(PIMAGE_DOS_HEADER	pDosHeader, PPEALIGNMENT pPeAlignment);

//获取节表数
DWORD	GetNumberOfSection(PIMAGE_DOS_HEADER	pDosHeader);
//获取第几个节表
PIMAGE_SECTION_HEADER	GetXXSectionHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial);
//获取节表属性
INT GetSectionCharacteristics(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial);

//获取合并的后的区段大小
DWORD	GetAllSizeOfSection(PIMAGE_DOS_HEADER pDosHeader);

//获取特定IMAGE_DATA_DIRECTORY的RVA
ULONG_PTR GetDataDirectoryRVA(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry);
//获取特定IMAGE_DATA_DIRECTORY的Size
ULONG_PTR GetDataDirectorySize(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectorySize);
//判断节区空间是否空余空间 >=0x50
BOOL	JudgeSize(PIMAGE_DOS_HEADER	pDosHeader);

//增加NumberOfSections
VOID AddNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	AddSectionNum);
//为一个节添加属性
VOID AddLSectionAttribute(PIMAGE_DOS_HEADER pDosHeader, DWORD Attribute, DWORD dwSerial);
//设置NumberOfSections
VOID SetNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	SectionNum);
//设置SizeOfImage
BOOL SetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSize);
//设置e_lfanew
VOID SetElfanew(PIMAGE_DOS_HEADER pDosHeader, LONG dwElfanew);
//扩大一个节的习惯，修改最后一个节表的SizeOfRawData 和 VirtualSize
VOID SetLastSectionRawDataAndVirtualSize(PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD dwSectionSize);
//设置SizeOfRawData和VirtualSize
VOID SetSizeOfRawDataAndVirtualSize(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, DWORD dwSize);
//设置第几个节的属性
VOID SetSectionCharacteristics(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, INT Characteristics);
//设置特定IMAGE_DATA_DIRECTORY的RVA
VOID SetDataDirectoryRVA(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry, DWORD dwVirtualAddress);
//设置特定IMAGE_DATA_DIRECTORY的Size
VOID SettDataDirectorySize(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry, DWORD dwSize);

//定义节属性
VOID AddSectionAttribute(PIMAGE_SECTION_HEADER pLastSectionHeader, INT Add);

//计算添加PointerToRawData和VirtualAddress
BOOL	CalcSectionTableAddress(PIMAGE_DOS_HEADER pDosHeader, PDWORD dwStartVirtualAddress, PDWORD dwStartFileAddress);

//扩展内存
PBYTE	StretchFileToMemory(PIMAGE_DOS_HEADER pDosHeader, PDWORD pFileSize);

//拷贝整个PE头
VOID CopyHeader(LPVOID	pDst, PIMAGE_DOS_HEADER	pDosHeader);

//拷贝区块
BOOL CopyAllSection(LPVOID	pMemory, PIMAGE_DOS_HEADER	pFile, DWORD dwSizeOfImage);

//拷贝导入表
BOOL CopyAndAddImportTable(PIMAGE_DOS_HEADER	pDosHeader, DWORD dwFileSize, DWORD dwExpandSize, PCHAR pDllName, PCHAR pFuncName);