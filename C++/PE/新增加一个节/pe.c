#include"pe.h"

PBYTE pZero = NULL;


//�ж�PE�ļ�
BOOL	IsPE(PIMAGE_DOS_HEADER pDosHeader) {
	BOOL bResult = FALSE;
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE && GetNtHeader(pDosHeader)->Signature == IMAGE_NT_SIGNATURE) {
		bResult = TRUE;
	}

	if (!bResult) {
		printf("[-]����PE\n");
	}
	return bResult;
}


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
DWORD GetSizeOfSectionTable(PIMAGE_DOS_HEADER pDosHeader) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
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
	DWORD	dwSizeOfDos = GetSizeOfDosAndStub(pDosHeader);
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);

	DWORD	dwSizeOfNtHeaders = GetSizeOfNtHeaders();
	DWORD	dwSizeOfSectionTable = GetSizeOfSectionTable(pDosHeader);;

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
VOID SetNumberOfSections(PIMAGE_NT_HEADERS pNtHeader, WORD	AddSectionNum) {
	pNtHeader->FileHeader.NumberOfSections += AddSectionNum;
}
//����SizeOfImage
BOOL AddSizeOfImage(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize) {
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-]����Dosͷ\n");
		return FALSE;
	}
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-]����Dosͷ\n");
		return FALSE;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwSectionSize;
	return TRUE;
}
//����e_lfanew
VOID SetElfanew(PIMAGE_DOS_HEADER pDosHeader, LONG dwElfanew) {
	pDosHeader->e_lfanew = dwElfanew;
}
//����һ���ڵ�ϰ�ߣ��޸����һ���ڱ��SizeOfRawData �� VirtualSize
VOID SetLastSectionRawDataAndVirtualSize(PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD dwSectionSize) {
	DWORD	dwMax = (pLastSectionHeader->SizeOfRawData >= pLastSectionHeader->Misc.VirtualSize ? pLastSectionHeader->SizeOfRawData : pLastSectionHeader->Misc.VirtualSize) + dwSectionSize;
	pLastSectionHeader->SizeOfRawData = pLastSectionHeader->Misc.VirtualSize = dwMax;
}

//���¶��������
VOID AddSectionAttribute(PIMAGE_SECTION_HEADER pLastSectionHeader, INT Add) {
	if (Add != NULL) {
		pLastSectionHeader->Characteristics |= Add;
	}

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

//��ȡDOS+DOS_Stub
DWORD	GetSizeOfDosAndStub(PIMAGE_DOS_HEADER pDosHeader) {
	return pDosHeader->e_lfanew;
}

DWORD	GetSizeOfDos() {
	return sizeof(IMAGE_DOS_HEADER);
}

//��ȡSectionHeader��С
DWORD GetSizeOfSectionHeader() {
	return sizeof(IMAGE_SECTION_HEADER);
}

//��ȡ�ڱ���
DWORD	GetNumberOfSection(PIMAGE_DOS_HEADER	pDosHeader) {
	return GetNtHeader(pDosHeader)->FileHeader.NumberOfSections;
}

//��ȡ�ڼ����ڱ�
PIMAGE_SECTION_HEADER	GetXXSectionHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial) {
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader(pDosHeader);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	return (PIMAGE_SECTION_HEADER)((ULONG_PTR)pFirstSectionHeader + (dwSerial - 1) * sizeof(IMAGE_SECTION_HEADER));
}

//�������PointerToRawData��VirtualAddress
BOOL	CalcSectionTableAddress(PIMAGE_DOS_HEADER pDosHeader, PDWORD pdwStartVirtualAddress, PDWORD pdwStartFileAddress) {
	PIMAGE_SECTION_HEADER pLastSectionHeader = NULL;
	PEALIGNMENT pPeAlignment = { 0 };
	//��ȡ���һ���εĲ���
	if (pZero != NULL) {
		pLastSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pZero - sizeof(IMAGE_SECTION_HEADER));
		GetAlignment(pDosHeader, &pPeAlignment);
	}
	else {
		printf("[-]ʶ�����һ���ڱ�ʧ��\n");
		return FALSE;
	}
	//���������ֵ
	*pdwStartVirtualAddress = GetStartAddress(pPeAlignment.SectionAlignment, pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->VirtualAddress);
	*pdwStartFileAddress = GetStartAddress(pPeAlignment.FileAlignment, pLastSectionHeader->SizeOfRawData, pLastSectionHeader->PointerToRawData);

	return TRUE;
}
