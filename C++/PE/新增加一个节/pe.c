#include"pe.h"

PBYTE pZero = NULL;

//��ȡNtHeader
PIMAGE_NT_HEADERS GetNtHeader(PIMAGE_DOS_HEADER pDosHeader) {
	DWORD	dwSizeOfDos = pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + dwSizeOfDos);
	return pNtHeader;
}

//��ȡNtHeaders��С
DWORD	GetSizeOfNtHeaders() {
	return sizeof(IMAGE_NT_HEADERS);
}

//��ȡSectionTable��С
DWORD GetSizeOfSectionTable(PIMAGE_NT_HEADERS pNtHeader) {
	return sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections);
}

//��ȡ�ڴ������ļ�����
VOID GetAlignment(PIMAGE_DOS_HEADER	pDosHeader, PPEALIGNMENT pPeAlignment) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);

	pPeAlignment->FileAlignment = pNtHeader->OptionalHeader.FileAlignment;
	pPeAlignment->SectionAlignment = pNtHeader->OptionalHeader.SectionAlignment;

}

//�жϽ����ռ��Ƿ����ռ� >=0x50
BOOL	JudgeSize(PIMAGE_DOS_HEADER	pDosHeader) {
	//DOS+DOS_Stub
	DWORD	dwSizeOfDos = pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + dwSizeOfDos);

	DWORD	dwSizeOfNtHeaders = sizeof(IMAGE_NT_HEADERS);
	DWORD	dwSizeOfSectionTable = sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections);

	DWORD	dwSizeOfNtAndSection = (dwSizeOfNtHeaders + dwSizeOfSectionTable);
	DWORD	dwDiff = pNtHeader->OptionalHeader.SizeOfHeaders - (dwSizeOfNtHeaders + dwSizeOfSectionTable);

	if (dwDiff >= 0x50) {
		//У���Ƿ�Ϊ0
		//ָ���հ״�
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

//����NumberOfSections
VOID SetNumberOfSections(PIMAGE_DOS_HEADER pDosHeader,WORD	AddSectionNum) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	pNtHeader->FileHeader.NumberOfSections += AddSectionNum;
}
//����SizeOfImage
VOID SetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader,DWORD dwSectionSize) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	pNtHeader->OptionalHeader.SizeOfImage += dwSectionSize;
}

//ȡģ�жϴ�С
DWORD	GetStartAddress(DWORD	dwAlignment, DWORD	dwSize, DWORD	dwAddress) {
	DWORD dwZero = dwSize % dwAlignment;
	DWORD dwDiv = dwSize / dwAlignment;
	if (dwZero != 0) {
		return dwAddress + (dwDiv + 1) * dwAlignment;
	}
	return dwSize + dwAddress;
}
