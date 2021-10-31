#include"pe.h"

PBYTE pZero = NULL;

//RVAToFileOffset
DWORD RVAToOffset(PIMAGE_DOS_HEADER pDosHeader,ULONG uRvaAddr) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	//��ȡ����ͷ�� 
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	//��ȡ���ε�����  --- nt���е��ļ�ͷ��  
	DWORD dwSize = pNtHeader->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < dwSize; i++) {
		if ((pSectionHeader[i].VirtualAddress <= uRvaAddr) &&
			((pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize) > uRvaAddr)) {
			return (uRvaAddr - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData);
		}
	}
	return 0;
}

//FileOffsetToRva
DWORD OffsetToRVA(PIMAGE_DOS_HEADER pDosHeader,ULONG uOffsetAddr) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);

	//��ȡ����ͷ�� 
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	//��ȡ���ε�����  --- nt���е��ļ�ͷ��  
	DWORD dwSize = pNtHeader->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < dwSize; i++) {
		if ((pSectionHeader[i].PointerToRawData <= uOffsetAddr) &&
			(pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData > uOffsetAddr)) {
			return (uOffsetAddr - pSectionHeader[i].PointerToRawData + pSectionHeader[i].VirtualAddress);
		}
	}
	return 0;
}

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

//��ǰλ���ж�
BOOL	IsCurrentBit(PIMAGE_DOS_HEADER pDosHeader) {
	PIMAGE_NT_HEADERS pNtheader = GetNtHeader(pDosHeader);
	WORD CurrentMachine = pNtheader->FileHeader.Machine;
#ifdef _WIN64
	if (CurrentMachine == IMAGE_FILE_MACHINE_I386) {
#else
	if (CurrentMachine == IMAGE_FILE_MACHINE_AMD64 || CurrentMachine == IMAGE_FILE_MACHINE_IA64) {
#endif // _WIN64
		printf("[-]��ǰ�汾���ԣ����л�����һ���汾\n");
		return FALSE;
	}
	return TRUE;
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
VOID AddNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	AddSectionNum) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	pNtHeader->FileHeader.NumberOfSections += AddSectionNum;
}
//����NumberOfSections
VOID SetNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	SectionNum) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	pNtHeader->FileHeader.NumberOfSections = SectionNum;
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
//����SizeOfImage
BOOL SetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSize) {
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-]����Dosͷ\n");
		return FALSE;
	}
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-]����Dosͷ\n");
		return FALSE;
	}
	pNtHeader->OptionalHeader.SizeOfImage = dwSize;
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

//���õڼ���SizeOfRawData��VirtualSize
VOID SetSizeOfRawDataAndVirtualSize(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, DWORD dwSize) {
	PIMAGE_SECTION_HEADER pSectionHeader = GetXXSectionHeader(pDosHeader, dwSerial);
	pSectionHeader->Misc.VirtualSize = pSectionHeader->SizeOfRawData = dwSize;
}
//���õڼ����ڵ�����
VOID SetSectionCharacteristics(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, INT Characteristics) {
	PIMAGE_SECTION_HEADER pSectionHeader = GetXXSectionHeader(pDosHeader, dwSerial);
	pSectionHeader->Characteristics = Characteristics;
}
//���¶��������
VOID AddSectionAttribute(PIMAGE_SECTION_HEADER pLastSectionHeader, INT Add) {
	if (Add != NULL) {
		pLastSectionHeader->Characteristics |= Add;
	}

}
//Ϊһ�����������
VOID AddLSectionAttribute(PIMAGE_DOS_HEADER pDosHeader, DWORD Attribute, DWORD dwSerial) {
	//��ȡһ���ڱ��޸�����
	PIMAGE_SECTION_HEADER pLastSectionHeader = GetXXSectionHeader(pDosHeader, dwSerial);
	//��ӽڱ�����
	AddSectionAttribute(pLastSectionHeader, Attribute);
}
//�����ض�IMAGE_DATA_DIRECTORY��RVA
VOID SetDataDirectoryRVA(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry, DWORD dwVirtualAddress) {
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader(pDosHeader);
	pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].VirtualAddress = dwVirtualAddress;
}
//�����ض�IMAGE_DATA_DIRECTORY��Size
VOID SettDataDirectorySize(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry, DWORD dwSize) {
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader(pDosHeader);
	pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].Size = dwSize;
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

//��ȡ�����С
DWORD GetAlign(DWORD	dwAlignment, DWORD	dwSize) {
	DWORD dwZero = dwSize % dwAlignment;
	DWORD dwDiv = dwSize / dwAlignment;
	if (dwZero != 0) {
		return   (dwDiv + 1) * dwAlignment;
	}
	return dwSize;
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

//��ȡ�ڱ�����
INT GetSectionCharacteristics(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial) {
	PIMAGE_SECTION_HEADER	pSectionHeader = GetXXSectionHeader(pDosHeader, dwSerial);
	return pSectionHeader->Characteristics;
}

//��ȡ�ϲ��ĺ�����δ�С
DWORD	GetAllSizeOfSection(PIMAGE_DOS_HEADER pDosHeader) {
	//��ȡ���һ���ڱ��ָ��
	PIMAGE_SECTION_HEADER pLastSectionHeader = GetXXSectionHeader(pDosHeader, GetNumberOfSection(pDosHeader));
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader(pDosHeader);
	PEALIGNMENT PeAlignment = { 0 };
	GetAlignment(pDosHeader, &PeAlignment);

	DWORD dwMax = pLastSectionHeader->SizeOfRawData > pLastSectionHeader->Misc.VirtualSize ? pLastSectionHeader->SizeOfRawData : pLastSectionHeader->Misc.VirtualSize;
	return pLastSectionHeader->VirtualAddress + dwMax - GetAlign(PeAlignment.SectionAlignment, pNtHeader->OptionalHeader.SizeOfHeaders);
}

//��ȡ�ض�IMAGE_DATA_DIRECTORY��RVA
ULONG_PTR GetDataDirectoryRVA(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry) {
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader(pDosHeader);
	return pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].VirtualAddress;
}
//��ȡ�ض�IMAGE_DATA_DIRECTORY��Size
ULONG_PTR GetDataDirectorySize(PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry) {
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader(pDosHeader);
	return pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].Size;
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


//��չ�ڴ�
PBYTE	StretchFileToMemory(PIMAGE_DOS_HEADER pDosHeader, PDWORD pFileSize) {
	//������� Ӳ�����ļ���ӳ��
	PBYTE	pMemory = NULL;
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	DWORD	dwSizeOfImage = *pFileSize = pNtHeader->OptionalHeader.SizeOfImage;
	DWORD	dwNumberOfSection = GetNumberOfSection(pDosHeader);

	pMemory = VirtualAlloc(NULL, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	ZeroMemory(pMemory, dwSizeOfImage);

	if (pMemory == NULL) {
		DEBUG_INFO("[-]����ռ�ʧ��\n");
		return NULL;
	}

	//��������PEͷ
	CopyHeader(pMemory, pDosHeader);
	//��������
	if (!CopyAllSection(pMemory, pDosHeader, dwSizeOfImage)) {
		VirtualFree(pMemory, 0, MEM_RELEASE);
		return NULL;
	}

	return pMemory;

}

//��������PEͷ
VOID CopyHeader(LPVOID	pDst, PIMAGE_DOS_HEADER	pDosHeader) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	DWORD	dwSizeOfHeader = pNtHeader->OptionalHeader.SizeOfHeaders;
	CopyMemory(pDst, pDosHeader, dwSizeOfHeader);
}

//��������
BOOL CopyAllSection(LPVOID	pMemory, PIMAGE_DOS_HEADER	pFile, DWORD dwSizeOfImage) {

	//��ȡSectionTable
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pFile);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_SECTION_HEADER pFirstSection = pSection;
	DWORD dwNumberOfSection = GetNumberOfSection(pFile);

	for (int i = 0; i < dwNumberOfSection; i++) {
		ULONG_PTR dwVirtualAddress = pSection->VirtualAddress;
		ULONG_PTR dwSizeOfRawData = pSection->SizeOfRawData;
		ULONG_PTR dwPointerToRawData = pSection->PointerToRawData;

		LPVOID lpRawOfData = (LPVOID)((ULONG_PTR)pFile + dwPointerToRawData);
		LPVOID lpMemory = (LPVOID)((ULONG_PTR)pMemory + dwVirtualAddress - pFirstSection->VirtualAddress + pFirstSection->PointerToRawData);

		if (((ULONG_PTR)lpMemory + dwSizeOfRawData) > ((ULONG_PTR)pMemory + dwSizeOfImage)) {
			DEBUG_INFO("[-]��Խ�߽�\n");
			return FALSE;
		}
		CopyMemory(lpMemory, lpRawOfData, dwSizeOfRawData);
		pSection++;
	}


}

BOOL CopyAndAddImportTable(PIMAGE_DOS_HEADER	pDosHeader, DWORD dwFileSize, DWORD dwExpandSize, PCHAR pDllName, PCHAR pFuncName) {
	BOOL bResult = TRUE;
	pZero = (PBYTE)((ULONG_PTR)pDosHeader + dwFileSize - dwExpandSize);
	PBYTE pImportTableHeader = pZero;
	DWORD	dwImportTableRva = GetDataDirectoryRVA(pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);
	DWORD	dwImportTableSize = GetDataDirectorySize(pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);

	PBYTE pImportTable = (PBYTE)((ULONG_PTR)pDosHeader + RVAToOffset(pDosHeader, dwImportTableRva));
	if (memcpy_s(pZero, dwExpandSize, pImportTable, dwImportTableSize)) {
		DEBUG_INFO("[-]���������ʧ��\n");
		bResult = FALSE;
	}
	else {
		pZero += dwImportTableSize - sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}


	DWORD	dwSizeOfFuncName = strlen(pFuncName) + 1;
	DWORD	dwSizeOfDllName = strlen(pDllName) + 1;
	//׷�ӵ����
	IMAGE_IMPORT_DESCRIPTOR NewImportDescriptor = { 0 };

	//��λ���ӵĵ����
	PIMAGE_IMPORT_DESCRIPTOR	pNewImport = pZero;
	pZero = (PBYTE)((ULONG_PTR)pNewImport + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	//׷��8���ֽڵ�INT��8���ֽڵ�IAT��
	//IAT / INT->PIMAGE_THUNK_DATA -> IMAGE_IMPORT_BY_NAME
	//INT IAT ָ��
	PIMAGE_THUNK_DATA pIATTable = (PIMAGE_THUNK_DATA)((ULONG_PTR)pZero + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	PIMAGE_THUNK_DATA pINTTable = (PIMAGE_THUNK_DATA)((ULONG_PTR)pIATTable + sizeof(IMAGE_THUNK_DATA));

	//׷��һ��DLL����
	PBYTE	pFileDllName = (PBYTE)((ULONG_PTR)pIATTable + 2 * sizeof(PIMAGE_THUNK_DATA));
	_memccpy(pFileDllName, pDllName, dwSizeOfDllName, dwSizeOfDllName);
	pNewImport->Name = OffsetToRVA(pDosHeader, (ULONG)pFileDllName - (ULONG)pDosHeader);

	//׷��һ�� IMAGE_IMPORT_BY_NAME�ṹ, ǰ2���ֽ���0�����Ǻ��������ַ���
	PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pFileDllName + dwSizeOfDllName);
	pImportByName->Hint = 0x01;
	_memccpy(pImportByName->Name, pFuncName, dwSizeOfFuncName, dwSizeOfFuncName);

	//��IMAGE_IMPORT_BY_NAME�ṹ��RVA��ֵ��INT��IAT���еĵ�һ��
	pNewImport->OriginalFirstThunk = OffsetToRVA(pDosHeader, (ULONG)pINTTable - (ULONG)pDosHeader);
	pNewImport->OriginalFirstThunk = 0;
	pNewImport->FirstThunk = OffsetToRVA(pDosHeader, (ULONG)pIATTable - (ULONG)pDosHeader);
	//pINTTable->u1.AddressOfData = pIATTable->u1.AddressOfData = OffsetToRVA(pDosHeader,(ULONG)pImportByName - (ULONG)pDosHeader);
	pIATTable->u1.AddressOfData = OffsetToRVA(pDosHeader, (ULONG)pImportByName - (ULONG)pDosHeader);

	//����IMAGE_DATA_DIRECT0RY�ṹ�� VirtualAddress��Sie
	DWORD	dwNewVirtualAddress = OffsetToRVA(pDosHeader, (ULONG)pImportTableHeader - (ULONG)pDosHeader);

	SetDataDirectoryRVA(pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT, dwNewVirtualAddress);
	SettDataDirectorySize(pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT, dwImportTableSize + sizeof(IMAGE_IMPORT_DESCRIPTOR));
	return bResult;
}