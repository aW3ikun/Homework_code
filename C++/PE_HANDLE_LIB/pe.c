#include"pe.h"

PBYTE pZero = NULL;

//RVAToFileOffset
DWORD RVAToOffset (PIMAGE_DOS_HEADER pDosHeader, ULONG uRvaAddr)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	//��ȡ����ͷ�� 
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION (pNtHeader);

	//��ȡ���ε�����  --- nt���е��ļ�ͷ��  
	DWORD dwSize = pNtHeader->FileHeader.NumberOfSections;

	for ( DWORD i = 0; i < dwSize; i++ ) {
		if ( ( pSectionHeader[i].VirtualAddress <= uRvaAddr ) &&
			( ( pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize ) > uRvaAddr ) ) {
			return ( uRvaAddr - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData );
		}
	}
	return 0;
}

//FileOffsetToRva
DWORD OffsetToRVA (PIMAGE_DOS_HEADER pDosHeader, ULONG uOffsetAddr)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);

	//��ȡ����ͷ�� 
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION (pNtHeader);

	//��ȡ���ε�����  --- nt���е��ļ�ͷ��  
	DWORD dwSize = pNtHeader->FileHeader.NumberOfSections;

	for ( DWORD i = 0; i < dwSize; i++ ) {
		if ( ( pSectionHeader[i].PointerToRawData <= uOffsetAddr ) &&
			( pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData > uOffsetAddr ) ) {
			return ( uOffsetAddr - pSectionHeader[i].PointerToRawData + pSectionHeader[i].VirtualAddress );
		}
	}
	return 0;
}

//�ж�PE�ļ�
BOOL	IsPE (PIMAGE_DOS_HEADER pDosHeader)
{

	BOOL bResult = FALSE;
	DWORD	dwSizeOfDos = pDosHeader->e_lfanew;
	if ( pDosHeader->e_magic == IMAGE_DOS_SIGNATURE ) {
		if ( dwSizeOfDos >= GetSizeOfDos ( ) && dwSizeOfDos < 1024 ) {
			if ( GetNtHeader (pDosHeader)->Signature == IMAGE_NT_SIGNATURE ) {
				bResult = TRUE;
			}
		}
	}

	if ( !bResult ) {
		DEBUG_INFO ("[-]����PE\n");
	}
	return bResult;
}

//��ǰλ���ж�
BOOL	IsCurrentBit (PIMAGE_DOS_HEADER pDosHeader)
{
	PIMAGE_NT_HEADERS pNtheader = GetNtHeader (pDosHeader);
	WORD CurrentMachine = pNtheader->FileHeader.Machine;
#ifdef _WIN64
	if ( CurrentMachine == IMAGE_FILE_MACHINE_I386 ) {
#else
	if ( CurrentMachine == IMAGE_FILE_MACHINE_AMD64 || CurrentMachine == IMAGE_FILE_MACHINE_IA64 ) {
#endif // _WIN64
		DEBUG_INFO ("[-]��ǰ�汾���ԣ����л�����һ���汾\n");
		return FALSE;
	}
	return TRUE;
}

//��ȡNtHeader
inline PIMAGE_NT_HEADERS GetNtHeader (PIMAGE_DOS_HEADER pDosHeader)
{
	DWORD	dwSizeOfDos = pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)( (ULONG_PTR)pDosHeader + dwSizeOfDos );
	return pNtHeader;
}

//��ȡNtHeaders��С
DWORD	GetSizeOfNtHeaders ( )
{
	return sizeof (IMAGE_NT_HEADERS);
}

//��ȡչ����Ĵ�С
DWORD	GetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	return pNtHeader->OptionalHeader.SizeOfImage;
}

//��ȡSectionTable��С
DWORD GetSizeOfSectionTable (PIMAGE_DOS_HEADER pDosHeader)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	return sizeof (IMAGE_SECTION_HEADER) * ( pNtHeader->FileHeader.NumberOfSections );
}

//��ȡ�ڴ������ļ�����
VOID GetAlignment (PIMAGE_DOS_HEADER	pDosHeader, PPEALIGNMENT pPeAlignment)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);

	pPeAlignment->FileAlignment = pNtHeader->OptionalHeader.FileAlignment;
	pPeAlignment->SectionAlignment = pNtHeader->OptionalHeader.SectionAlignment;

}

//�жϽ����ռ��Ƿ����ռ� >=0x50
BOOL	JudgeSize (PIMAGE_DOS_HEADER	pDosHeader)
{
	//DOS+DOS_Stub
	DWORD	dwSizeOfDos = GetSizeOfDosAndStub (pDosHeader);
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);

	DWORD	dwSizeOfNtHeaders = GetSizeOfNtHeaders ( );
	DWORD	dwSizeOfSectionTable = GetSizeOfSectionTable (pDosHeader);;

	DWORD	dwSizeOfNtAndSection = ( dwSizeOfNtHeaders + dwSizeOfSectionTable );
	DWORD	dwDiff = pNtHeader->OptionalHeader.SizeOfHeaders - ( dwSizeOfNtHeaders + dwSizeOfSectionTable );

	if ( dwDiff >= 0x50 ) {
		//У���Ƿ�Ϊ0
		//ָ���հ״�
		pZero = (PBYTE)( (ULONG_PTR)pNtHeader + dwSizeOfNtAndSection );
		for ( int i = 0; i < 0x50; i++ ) {
			if ( *( pZero + i ) != 0x00 ) {
				return FALSE;
			}
		}
		return TRUE;
	}
	return FALSE;
}

//����NumberOfSections
VOID AddNumberOfSections (PIMAGE_DOS_HEADER pDosHeader, WORD	AddSectionNum)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	pNtHeader->FileHeader.NumberOfSections += AddSectionNum;
}
//����NumberOfSections
VOID SetNumberOfSections (PIMAGE_DOS_HEADER pDosHeader, WORD	SectionNum)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	pNtHeader->FileHeader.NumberOfSections = SectionNum;
}

//����SizeOfImage
BOOL AddSizeOfImage (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize)
{
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		DEBUG_INFO ("[-]����Dosͷ\n");
		return FALSE;
	}
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		DEBUG_INFO ("[-]����Dosͷ\n");
		return FALSE;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwSectionSize;
	return TRUE;
}
//����SizeOfImage
BOOL SetSizeOfImage (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSize)
{
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		DEBUG_INFO ("[-]����Dosͷ\n");
		return FALSE;
	}
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		DEBUG_INFO ("[-]����Dosͷ\n");
		return FALSE;
	}
	pNtHeader->OptionalHeader.SizeOfImage = dwSize;
	return TRUE;
}
//����e_lfanew
VOID SetElfanew (PIMAGE_DOS_HEADER pDosHeader, LONG dwElfanew)
{
	pDosHeader->e_lfanew = dwElfanew;
}
//����һ���ڵ�ϰ�ߣ��޸����һ���ڱ��SizeOfRawData �� VirtualSize
VOID SetLastSectionRawDataAndVirtualSize (PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD dwSectionSize)
{
	DWORD	dwMax = ( pLastSectionHeader->SizeOfRawData >= pLastSectionHeader->Misc.VirtualSize ? pLastSectionHeader->SizeOfRawData : pLastSectionHeader->Misc.VirtualSize ) + dwSectionSize;

	pLastSectionHeader->SizeOfRawData = pLastSectionHeader->Misc.VirtualSize = dwMax;
}

//���õڼ���SizeOfRawData��VirtualSize
VOID SetSizeOfRawDataAndVirtualSize (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, DWORD dwSize)
{
	PIMAGE_SECTION_HEADER pSectionHeader = GetXXSectionHeader (pDosHeader, dwSerial);
	pSectionHeader->Misc.VirtualSize = pSectionHeader->SizeOfRawData = dwSize;
}
//���õڼ����ڵ�����
VOID SetSectionCharacteristics (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, INT Characteristics)
{
	PIMAGE_SECTION_HEADER pSectionHeader = GetXXSectionHeader (pDosHeader, dwSerial);
	pSectionHeader->Characteristics = Characteristics;
}
//���¶��������
VOID AddSectionAttribute (PIMAGE_SECTION_HEADER pLastSectionHeader, INT Add)
{
	if ( Add != NULL ) {
		pLastSectionHeader->Characteristics |= Add;
	}

}
//Ϊһ�����������
VOID AddLSectionAttribute (PIMAGE_DOS_HEADER pDosHeader, DWORD Attribute, DWORD dwSerial)
{
	//��ȡһ���ڱ��޸�����
	PIMAGE_SECTION_HEADER pLastSectionHeader = GetXXSectionHeader (pDosHeader, dwSerial);
	//��ӽڱ�����
	AddSectionAttribute (pLastSectionHeader, Attribute);
}
//�����ض�IMAGE_DATA_DIRECTORY��RVA
VOID SetDataDirectoryRVA (PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry, DWORD dwVirtualAddress)
{
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].VirtualAddress = dwVirtualAddress;
}
//�����ض�IMAGE_DATA_DIRECTORY��Size
VOID SettDataDirectorySize (PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry, DWORD dwSize)
{
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].Size = dwSize;
}


//ȡģ�жϴ�С
DWORD	GetStartAddress (DWORD	dwAlignment, DWORD	dwSize, DWORD	dwAddress)
{
	DWORD dwZero = dwSize % dwAlignment;
	DWORD dwDiv = dwSize / dwAlignment;
	if ( dwZero != 0 ) {
		return dwAddress + ( dwDiv + 1 ) * dwAlignment;
	}
	return dwSize + dwAddress;
}

//��ȡ�����С
DWORD GetAlign (DWORD	dwAlignment, DWORD	dwSize)
{
	DWORD dwZero = dwSize % dwAlignment;
	DWORD dwDiv = dwSize / dwAlignment;
	if ( dwZero != 0 ) {
		return   ( dwDiv + 1 ) * dwAlignment;
	}
	return dwSize;
}

//��ȡDOS+DOS_Stub
DWORD	GetSizeOfDosAndStub (PIMAGE_DOS_HEADER pDosHeader)
{
	return pDosHeader->e_lfanew;
}

inline  DWORD	GetSizeOfDos ( )
{
	return sizeof (IMAGE_DOS_HEADER);
}

//��ȡSectionHeader��С
DWORD GetSizeOfSectionHeader ( )
{
	return sizeof (IMAGE_SECTION_HEADER);
}

//��ȡ�ڱ���
inline DWORD	GetNumberOfSection (PIMAGE_DOS_HEADER	pDosHeader)
{
	return GetNtHeader (pDosHeader)->FileHeader.NumberOfSections;
}

//��ȡ�ڼ����ڱ� 
PIMAGE_SECTION_HEADER	GetXXSectionHeader (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial)
{
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = IMAGE_FIRST_SECTION (pNtHeader);
	return (PIMAGE_SECTION_HEADER)( (ULONG_PTR)pFirstSectionHeader + ( dwSerial - 1 ) * sizeof (IMAGE_SECTION_HEADER) );
}

//��ȡ�ڱ�����
INT GetSectionCharacteristics (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial)
{
	PIMAGE_SECTION_HEADER	pSectionHeader = GetXXSectionHeader (pDosHeader, dwSerial);
	return pSectionHeader->Characteristics;
}

//��ȡ�ϲ��ĺ�����δ�С
DWORD	GetAllSizeOfSection (PIMAGE_DOS_HEADER pDosHeader)
{
	//��ȡ���һ���ڱ��ָ��
	PIMAGE_SECTION_HEADER pLastSectionHeader = GetXXSectionHeader (pDosHeader, GetNumberOfSection (pDosHeader));
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	PEALIGNMENT PeAlignment = { 0 };
	GetAlignment (pDosHeader, &PeAlignment);

	DWORD dwMax = pLastSectionHeader->SizeOfRawData > pLastSectionHeader->Misc.VirtualSize ? pLastSectionHeader->SizeOfRawData : pLastSectionHeader->Misc.VirtualSize;
	return pLastSectionHeader->VirtualAddress + dwMax - GetAlign (PeAlignment.SectionAlignment, pNtHeader->OptionalHeader.SizeOfHeaders);
}

//��ȡ�ض�IMAGE_DATA_DIRECTORY��RVA
ULONG_PTR GetDataDirectoryRVA (PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry)
{
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	return pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].VirtualAddress;
}
//��ȡ�ض�IMAGE_DATA_DIRECTORY��Size
ULONG_PTR GetDataDirectorySize (PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry)
{
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	return pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].Size;
}


//�������PointerToRawData��VirtualAddress
BOOL	CalcSectionTableAddress (PIMAGE_DOS_HEADER pDosHeader, PDWORD pdwStartVirtualAddress, PDWORD pdwStartFileAddress)
{
	PIMAGE_SECTION_HEADER pLastSectionHeader = NULL;
	PEALIGNMENT pPeAlignment = { 0 };
	//��ȡ���һ���εĲ���
	if ( pZero != NULL ) {
		pLastSectionHeader = (PIMAGE_SECTION_HEADER)( (ULONG_PTR)pZero - sizeof (IMAGE_SECTION_HEADER) );
		GetAlignment (pDosHeader, &pPeAlignment);
	}
	else {
		DEBUG_INFO ("[-]ʶ�����һ���ڱ�ʧ��\n");
		return FALSE;
	}
	//���������ֵ
	*pdwStartVirtualAddress = GetStartAddress (pPeAlignment.SectionAlignment, pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->VirtualAddress);
	*pdwStartFileAddress = GetStartAddress (pPeAlignment.FileAlignment, pLastSectionHeader->SizeOfRawData, pLastSectionHeader->PointerToRawData);

	return TRUE;
}


//��չ�ڴ�
PBYTE	StretchFileToMemory (PIMAGE_DOS_HEADER pDosHeader, PDWORD pFileSize)
{
	//������� Ӳ�����ļ���ӳ��
	PBYTE	pMemory = NULL;
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	DWORD	dwSizeOfImage = *pFileSize = pNtHeader->OptionalHeader.SizeOfImage;
	DWORD	dwNumberOfSection = GetNumberOfSection (pDosHeader);

	pMemory = VirtualAlloc (NULL, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	ZeroMemory (pMemory, dwSizeOfImage);

	if ( pMemory == NULL ) {
		DEBUG_INFO ("[-]����ռ�ʧ��\n");
		return NULL;
	}

	//��������PEͷ
	CopyHeader (pMemory, pDosHeader);
	//��������
	if ( !CopyAllSection (pMemory, pDosHeader, dwSizeOfImage) ) {
		VirtualFree (pMemory, 0, MEM_RELEASE);
		return NULL;
	}

	return pMemory;

}

//��������PEͷ
VOID CopyHeader (LPVOID	pDst, PIMAGE_DOS_HEADER	pDosHeader)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	DWORD	dwSizeOfHeader = pNtHeader->OptionalHeader.SizeOfHeaders;
	//CopyMemory(pDst, pDosHeader, dwSizeOfHeader);
	while ( dwSizeOfHeader-- )
		*( (BYTE*)pDst )++ = *( (BYTE*)pDosHeader )++;
}

//��������
BOOL CopyAllSection (LPVOID	pMemory, PIMAGE_DOS_HEADER	pFile, DWORD dwSizeOfImage)
{

	//��ȡSectionTable
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pFile);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION (pNtHeader);
	PIMAGE_SECTION_HEADER pFirstSection = pSection;
	DWORD dwNumberOfSection = GetNumberOfSection (pFile);

	for ( int i = 0; i < dwNumberOfSection; i++ ) {
		ULONG_PTR dwVirtualAddress = pSection->VirtualAddress;
		ULONG_PTR dwSizeOfRawData = pSection->SizeOfRawData;
		ULONG_PTR dwPointerToRawData = pSection->PointerToRawData;

		LPVOID lpRawOfData = (LPVOID)( (ULONG_PTR)pFile + dwPointerToRawData );
		LPVOID lpMemory = (LPVOID)( (ULONG_PTR)pMemory + dwVirtualAddress - pFirstSection->VirtualAddress + pFirstSection->PointerToRawData );

		if ( ( (ULONG_PTR)lpMemory + dwSizeOfRawData ) > ((ULONG_PTR)pMemory + dwSizeOfImage) ) {
			DEBUG_INFO ("[-]��Խ�߽�\n");
			return FALSE;
		}
		//CopyMemory(lpMemory, lpRawOfData, dwSizeOfRawData);
		while ( dwSizeOfRawData-- )
			*( (BYTE*)lpMemory )++ = *( (BYTE*)lpRawOfData )++;
		pSection++;
	}


}

BOOL CopyAndAddImportTable (PIMAGE_DOS_HEADER	pDosHeader, DWORD dwFileSize, DWORD dwExpandSize, PCHAR pDllName, PCHAR pFuncName)
{
	BOOL bResult = TRUE;
	pZero = (PBYTE)( (ULONG_PTR)pDosHeader + dwFileSize - dwExpandSize );
	PBYTE pImportTableHeader = pZero;
	DWORD	dwImportTableRva = GetDataDirectoryRVA (pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);
	DWORD	dwImportTableSize = GetDataDirectorySize (pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);

	PBYTE pImportTable = (PBYTE)( (ULONG_PTR)pDosHeader + RVAToOffset (pDosHeader, dwImportTableRva) );
	if ( memcpy_s (pZero, dwExpandSize, pImportTable, dwImportTableSize) ) {
		DEBUG_INFO ("[-]���������ʧ��\n");
		bResult = FALSE;
	}
	else {
		pZero += dwImportTableSize - sizeof (IMAGE_IMPORT_DESCRIPTOR);
	}


	DWORD	dwSizeOfFuncName = strlen (pFuncName) + 1;
	DWORD	dwSizeOfDllName = strlen (pDllName) + 1;
	//׷�ӵ����
	IMAGE_IMPORT_DESCRIPTOR NewImportDescriptor = { 0 };

	//��λ���ӵĵ����
	PIMAGE_IMPORT_DESCRIPTOR	pNewImport = pZero;
	pZero = (PBYTE)( (ULONG_PTR)pNewImport + sizeof (IMAGE_IMPORT_DESCRIPTOR) );
	//׷��8���ֽڵ�INT��8���ֽڵ�IAT��
	//IAT / INT->PIMAGE_THUNK_DATA -> IMAGE_IMPORT_BY_NAME
	//INT IAT ָ��
	PIMAGE_THUNK_DATA pIATTable = (PIMAGE_THUNK_DATA)( (ULONG_PTR)pZero + sizeof (IMAGE_IMPORT_DESCRIPTOR) );
	PIMAGE_THUNK_DATA pINTTable = (PIMAGE_THUNK_DATA)( (ULONG_PTR)pIATTable + sizeof (IMAGE_THUNK_DATA) );

	//׷��һ��DLL����
	PBYTE	pFileDllName = (PBYTE)( (ULONG_PTR)pIATTable + 2 * sizeof (PIMAGE_THUNK_DATA) );
	_memccpy (pFileDllName, pDllName, dwSizeOfDllName, dwSizeOfDllName);
	pNewImport->Name = OffsetToRVA (pDosHeader, (ULONG)pFileDllName - (ULONG)pDosHeader);

	//׷��һ�� IMAGE_IMPORT_BY_NAME�ṹ, ǰ2���ֽ���0�����Ǻ��������ַ���
	PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)( (ULONG_PTR)pFileDllName + dwSizeOfDllName );
	pImportByName->Hint = 0x01;
	_memccpy (pImportByName->Name, pFuncName, dwSizeOfFuncName, dwSizeOfFuncName);

	//��IMAGE_IMPORT_BY_NAME�ṹ��RVA��ֵ��INT��IAT���еĵ�һ��
	pNewImport->OriginalFirstThunk = OffsetToRVA (pDosHeader, (ULONG)pINTTable - (ULONG)pDosHeader);
	pNewImport->OriginalFirstThunk = 0;
	pNewImport->FirstThunk = OffsetToRVA (pDosHeader, (ULONG)pIATTable - (ULONG)pDosHeader);
	//pINTTable->u1.AddressOfData = pIATTable->u1.AddressOfData = OffsetToRVA(pDosHeader,(ULONG)pImportByName - (ULONG)pDosHeader);
	pIATTable->u1.AddressOfData = OffsetToRVA (pDosHeader, (ULONG)pImportByName - (ULONG)pDosHeader);

	//����IMAGE_DATA_DIRECT0RY�ṹ�� VirtualAddress��Sie
	DWORD	dwNewVirtualAddress = OffsetToRVA (pDosHeader, (ULONG)pImportTableHeader - (ULONG)pDosHeader);

	SetDataDirectoryRVA (pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT, dwNewVirtualAddress);
	SettDataDirectorySize (pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT, dwImportTableSize + sizeof (IMAGE_IMPORT_DESCRIPTOR));
	return bResult;
}

//Shellcode �������
//��Ҫ���뺯����ַ
VOID ShellCodeRepairImportTable (
	PIMAGE_DOS_HEADER pDosHeader, GETPROCADDRESS pGetProcAddress, LOADLIBRARY pLoadLibrary)
{
	//ȫ����ULONG_PTR�ö��ģ�ǿת����
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	ULONG_PTR	uiRva = 0;

	//��������
	ULONG_PTR	uiImportTable = 0;
	ULONG_PTR	uiImportINT = 0;
	ULONG_PTR	uiImportIAT = 0;
	ULONG_PTR	uiImportByName = 0;

	//DLL���
	ULONG_PTR	uiLibraryAddr = 0;
	//DLL������
	ULONG_PTR	uiExportTable = 0;
	ULONG_PTR	uiExportEAT = 0;

	pNtHeader = GetNtHeader (pDosHeader);
	uiRva = GetDataDirectoryRVA (pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);

	if ( uiRva == 0 ) {
		DEBUG_INFO ("[+]û�е����\n");
		return;
	}

	//ָ�����ڱ�
	uiImportTable = (ULONG_PTR)pDosHeader + uiRva;

	//���������
	while ( ( (PIMAGE_IMPORT_DESCRIPTOR)uiImportTable )->Name ) {
		//��������ָ���DLL

		uiLibraryAddr = (ULONG_PTR)pLoadLibrary ((LPCSTR)( (ULONG_PTR)pDosHeader + ( (PIMAGE_IMPORT_DESCRIPTOR)uiImportTable )->Name ));

		//��ȡ������INT��
		uiImportINT = (ULONG_PTR)pDosHeader + ( (PIMAGE_IMPORT_DESCRIPTOR)uiImportTable )->OriginalFirstThunk;

		//��ȡ������IAT��
		uiImportIAT = (ULONG_PTR)pDosHeader + ( (PIMAGE_IMPORT_DESCRIPTOR)uiImportTable )->FirstThunk;

		//ʹ�����ֽ��л�ȡ�����û��ʹ������ʹ����Ž��л�ȡ
		while ( DEREF(uiImportIAT) )
		{
			//if(IMAGE_SNAP_BY_ORDINAL((PIMAGE_THUNK_DATA)uiImportINT)->u1.Ordinal ){
			if ( uiImportIAT && ( (PIMAGE_THUNK_DATA)uiImportIAT )->u1.AddressOfData & IMAGE_ORDINAL_FLAG ) {
				//��ȡ��DLL�ĵ������ַ
				uiExportTable = uiLibraryAddr + (ULONG_PTR)GetDataDirectoryRVA((PIMAGE_DOS_HEADER)uiLibraryAddr, IMAGE_DIRECTORY_ENTRY_EXPORT);

				//��ȡ��ַ��
				uiExportEAT = uiLibraryAddr + (ULONG_PTR)( ( (PIMAGE_EXPORT_DIRECTORY)uiExportTable )->AddressOfFunctions );

				//��ȡ���뺯����ַ��RVA
				uiExportEAT += ( ( IMAGE_ORDINAL(( ( (PIMAGE_THUNK_DATA)uiImportINT )->u1.Ordinal ) - ( ( (PIMAGE_EXPORT_DIRECTORY)uiExportTable )->Base )) ) * sizeof(DWORD) );

				DEREF(uiImportIAT) = ( uiLibraryAddr + DEREF(uiExportEAT) );

			}
			else {
				//����IMAGE_IMPORT_BY_NAME��ȡ��������
				uiImportByName = ( (ULONG_PTR)pDosHeader + DEREF(uiImportIAT) );

				DEREF(uiImportIAT) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddr, (LPCSTR)( ( (PIMAGE_IMPORT_BY_NAME)uiImportByName ) )->Name);
			}
			uiImportIAT += sizeof(ULONG_PTR);
			if ( uiImportINT )
				uiImportINT += sizeof(ULONG_PTR);
		}

		//������һ����
		uiImportTable += sizeof (IMAGE_IMPORT_DESCRIPTOR);
	}


}
//=================================================
//����Ż�(��ѡ��С) (/O1)
// ֻ������ __inline (/Ob1)
//=================================================


//ShellCode�����ض�λ
VOID	ShellCodeFixReloc(PIMAGE_DOS_HEADER	pMemory, PIMAGE_DOS_HEADER pDosHeader)
{
	//��Ҫ��ӵĲ�ֵ
	LONG_PTR	uiValue = 0;

	//ָ���ض�λ���ĵ�VA
	ULONG_PTR	uiMemVa = 0;

	//��ȡ�����ض�λ��
	ULONG_PTR	uiReloc = 0;
	ULONG_PTR	uiRva = 0;
	ULONG_PTR	uiBlockNum = 0;
	ULONG_PTR	uiBlock = 0;

	//�����ֵ
	uiValue = (LONG_PTR)pMemory - GetNtHeader(pDosHeader)->OptionalHeader.ImageBase;
	if ( uiRva = (ULONG_PTR)GetDataDirectoryRVA(pMemory, IMAGE_DIRECTORY_ENTRY_BASERELOC) )
	{
		uiReloc = (ULONG_PTR)pMemory + uiRva;

		//������������
		while ( ( (PIMAGE_BASE_RELOCATION)uiReloc )->SizeOfBlock ) 
		{
			//��λ�鿪ͷ
			uiMemVa = (ULONG_PTR)pMemory + (ULONG_PTR)( ( (PIMAGE_BASE_RELOCATION)uiReloc )->VirtualAddress );

			//��ȡ������
			uiBlockNum = (ULONG_PTR)(( ( (PIMAGE_BASE_RELOCATION)uiReloc )->SizeOfBlock ) - sizeof(IMAGE_BASE_RELOCATION) / sizeof(IMAGE_RELOC));

			//��λһ����
			uiBlock = uiReloc + sizeof(IMAGE_BASE_RELOCATION);

			//VirtualAddress(1000) + Offset(420) = 1420(RVA)
			//�ټ���ImageBase
			
			while ( uiBlockNum-- ) {
				if ( ( (PIMAGE_RELOC)uiBlock )->type == IMAGE_REL_BASED_DIR64 )
					DEREF_ULONGPTR(uiMemVa + ( (PIMAGE_RELOC)uiBlock )->offset) += uiValue;
				else if ( ( (PIMAGE_RELOC)uiBlock )->type == IMAGE_REL_BASED_HIGHLOW )
					DEREF_DWORD(uiMemVa + ( (PIMAGE_RELOC)uiBlock )->offset) += (DWORD)uiValue;
				else if ( ( (PIMAGE_RELOC)uiBlock )->type == IMAGE_REL_BASED_HIGH )
					DEREF_WORD(uiMemVa + ( (PIMAGE_RELOC)uiBlock )->offset) += HIWORD(uiValue);
				else if ( ( (PIMAGE_RELOC)uiBlock )->type == IMAGE_REL_BASED_LOW )
					DEREF_WORD(uiMemVa + ( (PIMAGE_RELOC)uiBlock )->offset) += LOWORD (uiValue);

				uiBlock += sizeof(IMAGE_RELOC);
			}


			//����������������
			uiReloc += (ULONG_PTR)( ( (PIMAGE_BASE_RELOCATION)uiReloc )->SizeOfBlock );
		}

	}
}

//ShellCode ��Ѱδչ����������
DWORD	GetFileExportFunctionOffset(PIMAGE_DOS_HEADER	pDosHeader, PCHAR pFuncName)
{

	ULONG_PTR uiRva = 0;
	DWORD dwCounter = 0;

	PIMAGE_EXPORT_DIRECTORY pExportDirect = NULL;
	PDWORD pEAT = NULL;
	PDWORD pENT = NULL;
	PWORD pEOT = NULL;
	//У��汾
#ifdef _WIN64
	DWORD dwCompiledArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD dwCompiledArch = 1;
#endif
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);

	if ( pNtHeader->OptionalHeader.Magic == 0x010B ) // PE32
	{
		if ( dwCompiledArch != 1 )
			return 0;
	}
	else if ( pNtHeader->OptionalHeader.Magic == 0x020B ) // PE64
	{
		if ( dwCompiledArch != 2 )
			return 0;
	}
	else
	{
		return 0;
	}
	uiRva = GetDataDirectoryRVA(pDosHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);

	//ָ���ļ�ƫ�Ƶĵ�����
	pExportDirect = (PIMAGE_EXPORT_DIRECTORY)( (ULONG_PTR)pDosHeader + RVAToOffset(pDosHeader, uiRva) );

	//ָ��EAT��DWORD����
	pEAT = (PDWORD)( (ULONG_PTR)pDosHeader + RVAToOffset(pDosHeader, pExportDirect->AddressOfFunctions) );

	//ָ��ENT��DOWRD����
	pENT = (PDWORD)( (ULONG_PTR)pDosHeader + RVAToOffset(pDosHeader, pExportDirect->AddressOfNames) );

	//ָ��EOT��WORD����
	pEOT = (PWORD)( (ULONG_PTR)pDosHeader + RVAToOffset(pDosHeader, pExportDirect->AddressOfNameOrdinals) );

	dwCounter = pExportDirect->NumberOfNames;

	while ( dwCounter-- ) {
		PCHAR ExportFunctionName = (PCHAR)( (ULONG_PTR)pDosHeader + RVAToOffset(pDosHeader, *pENT) );

		if ( strstr(ExportFunctionName, pFuncName) != NULL ) {
			pEAT += *pEOT;

			return RVAToOffset(pDosHeader, *pEAT);
		}
		pENT++;
		pEOT++;

	}

	return 0;

}