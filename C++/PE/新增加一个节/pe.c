#include"pe.h"

PBYTE pZero = NULL;


//判断PE文件
BOOL	IsPE(PIMAGE_DOS_HEADER pDosHeader) {
	BOOL bResult = FALSE;
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE && GetNtHeader(pDosHeader)->Signature == IMAGE_NT_SIGNATURE) {
		bResult = TRUE;
	}

	if (!bResult) {
		printf("[-]不是PE\n");
	}
	return bResult;
}


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
DWORD GetSizeOfSectionTable(PIMAGE_DOS_HEADER pDosHeader) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
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
	DWORD	dwSizeOfDos = GetSizeOfDosAndStub(pDosHeader);
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);

	DWORD	dwSizeOfNtHeaders = GetSizeOfNtHeaders();
	DWORD	dwSizeOfSectionTable = GetSizeOfSectionTable(pDosHeader);;

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
VOID AddNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	AddSectionNum) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	pNtHeader->FileHeader.NumberOfSections += AddSectionNum;
}
//设置NumberOfSections
VOID SetNumberOfSections(PIMAGE_DOS_HEADER pDosHeader, WORD	SectionNum) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	pNtHeader->FileHeader.NumberOfSections= SectionNum;
}

//设置SizeOfImage
BOOL AddSizeOfImage(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize) {
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-]不是Dos头\n");
		return FALSE;
	}
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-]不是Dos头\n");
		return FALSE;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwSectionSize;
	return TRUE;
}
//设置SizeOfImage
BOOL SetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSize) {
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-]不是Dos头\n");
		return FALSE;
	}
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-]不是Dos头\n");
		return FALSE;
	}
	pNtHeader->OptionalHeader.SizeOfImage = dwSize;
	return TRUE;
}
//设置e_lfanew
VOID SetElfanew(PIMAGE_DOS_HEADER pDosHeader, LONG dwElfanew) {
	pDosHeader->e_lfanew = dwElfanew;
}
//扩大一个节的习惯，修改最后一个节表的SizeOfRawData 和 VirtualSize
VOID SetLastSectionRawDataAndVirtualSize(PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD dwSectionSize) {
	DWORD	dwMax = (pLastSectionHeader->SizeOfRawData >= pLastSectionHeader->Misc.VirtualSize ? pLastSectionHeader->SizeOfRawData : pLastSectionHeader->Misc.VirtualSize) + dwSectionSize;
	pLastSectionHeader->SizeOfRawData = pLastSectionHeader->Misc.VirtualSize = dwMax;
}

//设置第几个SizeOfRawData和VirtualSize
VOID SetSizeOfRawDataAndVirtualSize(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, DWORD dwSize) {
	PIMAGE_SECTION_HEADER pSectionHeader = GetXXSectionHeader(pDosHeader, dwSerial);
	pSectionHeader->Misc.VirtualSize = pSectionHeader->SizeOfRawData = dwSize;
}
//设置第几个节的属性
VOID SetSectionCharacteristics(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, INT Characteristics) {
	PIMAGE_SECTION_HEADER pSectionHeader = GetXXSectionHeader(pDosHeader, dwSerial);
	pSectionHeader->Characteristics = Characteristics;
}
//重新定义节属性
VOID AddSectionAttribute(PIMAGE_SECTION_HEADER pLastSectionHeader, INT Add) {
	if (Add != NULL) {
		pLastSectionHeader->Characteristics |= Add;
	}

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

//获取对齐大小
DWORD GetAlign(DWORD	dwAlignment, DWORD	dwSize) {
	DWORD dwZero = dwSize % dwAlignment;
	DWORD dwDiv = dwSize / dwAlignment;
	if (dwZero != 0) {
		return   (dwDiv + 1) * dwAlignment;
	}
	return dwSize;
}

//获取DOS+DOS_Stub
DWORD	GetSizeOfDosAndStub(PIMAGE_DOS_HEADER pDosHeader) {
	return pDosHeader->e_lfanew;
}

DWORD	GetSizeOfDos() {
	return sizeof(IMAGE_DOS_HEADER);
}

//获取SectionHeader大小
DWORD GetSizeOfSectionHeader() {
	return sizeof(IMAGE_SECTION_HEADER);
}

//获取节表数
DWORD	GetNumberOfSection(PIMAGE_DOS_HEADER	pDosHeader) {
	return GetNtHeader(pDosHeader)->FileHeader.NumberOfSections;
}

//获取第几个节表 
PIMAGE_SECTION_HEADER	GetXXSectionHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial) {
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader(pDosHeader);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	return (PIMAGE_SECTION_HEADER)((ULONG_PTR)pFirstSectionHeader + (dwSerial - 1) * sizeof(IMAGE_SECTION_HEADER));
}

//获取节表属性
INT GetSectionCharacteristics(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial) {
	PIMAGE_SECTION_HEADER	pSectionHeader = GetXXSectionHeader(pDosHeader, dwSerial);
	return pSectionHeader->Characteristics;
}

//获取合并的后的区段大小
DWORD	GetAllSizeOfSection(PIMAGE_DOS_HEADER pDosHeader) {
	//获取最后一个节表的指针
	PIMAGE_SECTION_HEADER pLastSectionHeader = GetXXSectionHeader(pDosHeader, GetNumberOfSection(pDosHeader));
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader(pDosHeader);
	PEALIGNMENT PeAlignment = { 0 };
	GetAlignment(pDosHeader, &PeAlignment);

	DWORD dwMax = pLastSectionHeader->SizeOfRawData > pLastSectionHeader->Misc.VirtualSize ? pLastSectionHeader->SizeOfRawData : pLastSectionHeader->Misc.VirtualSize;
	return pLastSectionHeader->VirtualAddress + dwMax - GetAlign(PeAlignment.SectionAlignment,pNtHeader->OptionalHeader.SizeOfHeaders );
}

//计算添加PointerToRawData和VirtualAddress
BOOL	CalcSectionTableAddress(PIMAGE_DOS_HEADER pDosHeader, PDWORD pdwStartVirtualAddress, PDWORD pdwStartFileAddress) {
	PIMAGE_SECTION_HEADER pLastSectionHeader = NULL;
	PEALIGNMENT pPeAlignment = { 0 };
	//获取最后一个段的参数
	if (pZero != NULL) {
		pLastSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pZero - sizeof(IMAGE_SECTION_HEADER));
		GetAlignment(pDosHeader, &pPeAlignment);
	}
	else {
		printf("[-]识别最后一个节表失败\n");
		return FALSE;
	}
	//计算该填充的值
	*pdwStartVirtualAddress = GetStartAddress(pPeAlignment.SectionAlignment, pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->VirtualAddress);
	*pdwStartFileAddress = GetStartAddress(pPeAlignment.FileAlignment, pLastSectionHeader->SizeOfRawData, pLastSectionHeader->PointerToRawData);

	return TRUE;
}


//扩展内存
PBYTE	StretchFileToMemory(PIMAGE_DOS_HEADER pDosHeader,PDWORD pFileSize) {
	//传入的是 硬盘中文件的映射
	PBYTE	pMemory = NULL;
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	DWORD	dwSizeOfImage = *pFileSize = pNtHeader->OptionalHeader.SizeOfImage;
	DWORD	dwNumberOfSection = GetNumberOfSection(pDosHeader);

	pMemory = VirtualAlloc(NULL, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	ZeroMemory(pMemory, dwSizeOfImage);

	if (pMemory == NULL) {
		DEBUG_INFO("[-]申请空间失败\n");
		return NULL;
	}

	//拷贝整个PE头
	CopyHeader(pMemory, pDosHeader);
	//拷贝区块
	if (!CopyAllSection(pMemory, pDosHeader, dwSizeOfImage)) {
		VirtualFree(pMemory, 0, MEM_RELEASE);
		return NULL;
	}

	return pMemory;

}

//拷贝整个PE头
VOID CopyHeader(LPVOID	pDst, PIMAGE_DOS_HEADER	pDosHeader) {
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	DWORD	dwSizeOfHeader = pNtHeader->OptionalHeader.SizeOfHeaders;
	CopyMemory(pDst, pDosHeader, dwSizeOfHeader);
}

//拷贝区块
BOOL CopyAllSection(LPVOID	pMemory, PIMAGE_DOS_HEADER	pFile,DWORD dwSizeOfImage) {

	//获取SectionTable
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
			DEBUG_INFO("[-]超越边界\n");
			return FALSE;
		}
		CopyMemory(lpMemory, lpRawOfData, dwSizeOfRawData);
		pSection++;
	}


}