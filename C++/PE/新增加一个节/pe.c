#include"pe.h"

PBYTE pZero = NULL;

//获取NtHeader
PIMAGE_NT_HEADERS GetNtHeader(PIMAGE_DOS_HEADER pDosHeader) {
	DWORD	dwSizeOfDos = pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + dwSizeOfDos);
	return pNtHeader;
}

//获取NtHeaders大小
DWORD	GetSizeOfNtHeaders() {
	return sizeof(IMAGE_NT_HEADERS);
}

//获取SectionTable大小
DWORD GetSizeOfSectionTable(PIMAGE_NT_HEADERS pNtHeader) {
	return sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections);
}

//获取内存对齐和文件对齐
VOID GetAlignment(PIMAGE_DOS_HEADER	pDosHeader, PPEALIGNMENT pPeAlignment) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);

	pPeAlignment->FileAlignment = pNtHeader->OptionalHeader.FileAlignment;
	pPeAlignment->SectionAlignment = pNtHeader->OptionalHeader.SectionAlignment;

}

//判断节区空间是否空余空间 >=0x50
BOOL	JudgeSize(PIMAGE_DOS_HEADER	pDosHeader) {
	//DOS+DOS_Stub
	DWORD	dwSizeOfDos = pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + dwSizeOfDos);

	DWORD	dwSizeOfNtHeaders = sizeof(IMAGE_NT_HEADERS);
	DWORD	dwSizeOfSectionTable = sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections);

	DWORD	dwSizeOfNtAndSection = (dwSizeOfNtHeaders + dwSizeOfSectionTable);
	DWORD	dwDiff = pNtHeader->OptionalHeader.SizeOfHeaders - (dwSizeOfNtHeaders + dwSizeOfSectionTable);

	if (dwDiff >= 0x50) {
		//校验是否都为0
		//指到空白处
		pZero = (PBYTE)((ULONG_PTR)pNtHeader + dwSizeOfNtAndSection);
		for (int i = 0; i < 0x50; i++) {
			if (*(pZero + i) != 0x00) {
				return FALSE;
			}
		}
		return TRUE;
	}
	return FALSE;
}

//设置NumberOfSections
VOID SetNumberOfSections(PIMAGE_DOS_HEADER pDosHeader,WORD	AddSectionNum) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	pNtHeader->FileHeader.NumberOfSections += AddSectionNum;
}
//设置SizeOfImage
VOID SetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader,DWORD dwSectionSize) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	pNtHeader->OptionalHeader.SizeOfImage += dwSectionSize;
}

//取模判断大小
DWORD	GetStartAddress(DWORD	dwAlignment, DWORD	dwSize, DWORD	dwAddress) {
	DWORD dwZero = dwSize % dwAlignment;
	DWORD dwDiv = dwSize / dwAlignment;
	if (dwZero != 0) {
		return dwAddress + (dwDiv + 1) * dwAlignment;
	}
	return dwSize + dwAddress;
}
