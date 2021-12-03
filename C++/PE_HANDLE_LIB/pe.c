#include"pe.h"

PBYTE pZero = NULL;

//RVAToFileOffset
DWORD RVAToOffset (PIMAGE_DOS_HEADER pDosHeader, ULONG uRvaAddr)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	//获取区段头表 
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION (pNtHeader);

	//获取区段的数量  --- nt表中的文件头中  
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

	//获取区段头表 
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION (pNtHeader);

	//获取区段的数量  --- nt表中的文件头中  
	DWORD dwSize = pNtHeader->FileHeader.NumberOfSections;

	for ( DWORD i = 0; i < dwSize; i++ ) {
		if ( ( pSectionHeader[i].PointerToRawData <= uOffsetAddr ) &&
			( pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData > uOffsetAddr ) ) {
			return ( uOffsetAddr - pSectionHeader[i].PointerToRawData + pSectionHeader[i].VirtualAddress );
		}
	}
	return 0;
}

//判断PE文件
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
		DEBUG_INFO ("[-]不是PE\n");
	}
	return bResult;
}

//当前位数判断
BOOL	IsCurrentBit (PIMAGE_DOS_HEADER pDosHeader)
{
	PIMAGE_NT_HEADERS pNtheader = GetNtHeader (pDosHeader);
	WORD CurrentMachine = pNtheader->FileHeader.Machine;
#ifdef _WIN64
	if ( CurrentMachine == IMAGE_FILE_MACHINE_I386 ) {
#else
	if ( CurrentMachine == IMAGE_FILE_MACHINE_AMD64 || CurrentMachine == IMAGE_FILE_MACHINE_IA64 ) {
#endif // _WIN64
		DEBUG_INFO ("[-]当前版本不对，请切换成另一个版本\n");
		return FALSE;
	}
	return TRUE;
}

//获取NtHeader
inline PIMAGE_NT_HEADERS GetNtHeader (PIMAGE_DOS_HEADER pDosHeader)
{
	DWORD	dwSizeOfDos = pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)( (ULONG_PTR)pDosHeader + dwSizeOfDos );
	return pNtHeader;
}

//获取NtHeaders大小
DWORD	GetSizeOfNtHeaders ( )
{
	return sizeof (IMAGE_NT_HEADERS);
}

//获取展开后的大小
DWORD	GetSizeOfImage(PIMAGE_DOS_HEADER pDosHeader)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	return pNtHeader->OptionalHeader.SizeOfImage;
}

//获取SectionTable大小
DWORD GetSizeOfSectionTable (PIMAGE_DOS_HEADER pDosHeader)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	return sizeof (IMAGE_SECTION_HEADER) * ( pNtHeader->FileHeader.NumberOfSections );
}

//获取内存对齐和文件对齐
VOID GetAlignment (PIMAGE_DOS_HEADER	pDosHeader, PPEALIGNMENT pPeAlignment)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);

	pPeAlignment->FileAlignment = pNtHeader->OptionalHeader.FileAlignment;
	pPeAlignment->SectionAlignment = pNtHeader->OptionalHeader.SectionAlignment;

}

//判断节区空间是否空余空间 >=0x50
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
		//校验是否都为0
		//指到空白处
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

//设置NumberOfSections
VOID AddNumberOfSections (PIMAGE_DOS_HEADER pDosHeader, WORD	AddSectionNum)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	pNtHeader->FileHeader.NumberOfSections += AddSectionNum;
}
//设置NumberOfSections
VOID SetNumberOfSections (PIMAGE_DOS_HEADER pDosHeader, WORD	SectionNum)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	pNtHeader->FileHeader.NumberOfSections = SectionNum;
}

//设置SizeOfImage
BOOL AddSizeOfImage (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize)
{
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		DEBUG_INFO ("[-]不是Dos头\n");
		return FALSE;
	}
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		DEBUG_INFO ("[-]不是Dos头\n");
		return FALSE;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwSectionSize;
	return TRUE;
}
//设置SizeOfImage
BOOL SetSizeOfImage (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSize)
{
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		DEBUG_INFO ("[-]不是Dos头\n");
		return FALSE;
	}
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
		DEBUG_INFO ("[-]不是Dos头\n");
		return FALSE;
	}
	pNtHeader->OptionalHeader.SizeOfImage = dwSize;
	return TRUE;
}
//设置e_lfanew
VOID SetElfanew (PIMAGE_DOS_HEADER pDosHeader, LONG dwElfanew)
{
	pDosHeader->e_lfanew = dwElfanew;
}
//扩大一个节的习惯，修改最后一个节表的SizeOfRawData 和 VirtualSize
VOID SetLastSectionRawDataAndVirtualSize (PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD dwSectionSize)
{
	DWORD	dwMax = ( pLastSectionHeader->SizeOfRawData >= pLastSectionHeader->Misc.VirtualSize ? pLastSectionHeader->SizeOfRawData : pLastSectionHeader->Misc.VirtualSize ) + dwSectionSize;

	pLastSectionHeader->SizeOfRawData = pLastSectionHeader->Misc.VirtualSize = dwMax;
}

//设置第几个SizeOfRawData和VirtualSize
VOID SetSizeOfRawDataAndVirtualSize (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, DWORD dwSize)
{
	PIMAGE_SECTION_HEADER pSectionHeader = GetXXSectionHeader (pDosHeader, dwSerial);
	pSectionHeader->Misc.VirtualSize = pSectionHeader->SizeOfRawData = dwSize;
}
//设置第几个节的属性
VOID SetSectionCharacteristics (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial, INT Characteristics)
{
	PIMAGE_SECTION_HEADER pSectionHeader = GetXXSectionHeader (pDosHeader, dwSerial);
	pSectionHeader->Characteristics = Characteristics;
}
//重新定义节属性
VOID AddSectionAttribute (PIMAGE_SECTION_HEADER pLastSectionHeader, INT Add)
{
	if ( Add != NULL ) {
		pLastSectionHeader->Characteristics |= Add;
	}

}
//为一个节添加属性
VOID AddLSectionAttribute (PIMAGE_DOS_HEADER pDosHeader, DWORD Attribute, DWORD dwSerial)
{
	//获取一个节表，修改属性
	PIMAGE_SECTION_HEADER pLastSectionHeader = GetXXSectionHeader (pDosHeader, dwSerial);
	//添加节表属性
	AddSectionAttribute (pLastSectionHeader, Attribute);
}
//设置特定IMAGE_DATA_DIRECTORY的RVA
VOID SetDataDirectoryRVA (PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry, DWORD dwVirtualAddress)
{
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].VirtualAddress = dwVirtualAddress;
}
//设置特定IMAGE_DATA_DIRECTORY的Size
VOID SettDataDirectorySize (PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry, DWORD dwSize)
{
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].Size = dwSize;
}


//取模判断大小
DWORD	GetStartAddress (DWORD	dwAlignment, DWORD	dwSize, DWORD	dwAddress)
{
	DWORD dwZero = dwSize % dwAlignment;
	DWORD dwDiv = dwSize / dwAlignment;
	if ( dwZero != 0 ) {
		return dwAddress + ( dwDiv + 1 ) * dwAlignment;
	}
	return dwSize + dwAddress;
}

//获取对齐大小
DWORD GetAlign (DWORD	dwAlignment, DWORD	dwSize)
{
	DWORD dwZero = dwSize % dwAlignment;
	DWORD dwDiv = dwSize / dwAlignment;
	if ( dwZero != 0 ) {
		return   ( dwDiv + 1 ) * dwAlignment;
	}
	return dwSize;
}

//获取DOS+DOS_Stub
DWORD	GetSizeOfDosAndStub (PIMAGE_DOS_HEADER pDosHeader)
{
	return pDosHeader->e_lfanew;
}

inline  DWORD	GetSizeOfDos ( )
{
	return sizeof (IMAGE_DOS_HEADER);
}

//获取SectionHeader大小
DWORD GetSizeOfSectionHeader ( )
{
	return sizeof (IMAGE_SECTION_HEADER);
}

//获取节表数
inline DWORD	GetNumberOfSection (PIMAGE_DOS_HEADER	pDosHeader)
{
	return GetNtHeader (pDosHeader)->FileHeader.NumberOfSections;
}

//获取第几个节表 
PIMAGE_SECTION_HEADER	GetXXSectionHeader (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial)
{
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	PIMAGE_SECTION_HEADER pFirstSectionHeader = IMAGE_FIRST_SECTION (pNtHeader);
	return (PIMAGE_SECTION_HEADER)( (ULONG_PTR)pFirstSectionHeader + ( dwSerial - 1 ) * sizeof (IMAGE_SECTION_HEADER) );
}

//获取节表属性
INT GetSectionCharacteristics (PIMAGE_DOS_HEADER pDosHeader, DWORD dwSerial)
{
	PIMAGE_SECTION_HEADER	pSectionHeader = GetXXSectionHeader (pDosHeader, dwSerial);
	return pSectionHeader->Characteristics;
}

//获取合并的后的区段大小
DWORD	GetAllSizeOfSection (PIMAGE_DOS_HEADER pDosHeader)
{
	//获取最后一个节表的指针
	PIMAGE_SECTION_HEADER pLastSectionHeader = GetXXSectionHeader (pDosHeader, GetNumberOfSection (pDosHeader));
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	PEALIGNMENT PeAlignment = { 0 };
	GetAlignment (pDosHeader, &PeAlignment);

	DWORD dwMax = pLastSectionHeader->SizeOfRawData > pLastSectionHeader->Misc.VirtualSize ? pLastSectionHeader->SizeOfRawData : pLastSectionHeader->Misc.VirtualSize;
	return pLastSectionHeader->VirtualAddress + dwMax - GetAlign (PeAlignment.SectionAlignment, pNtHeader->OptionalHeader.SizeOfHeaders);
}

//获取特定IMAGE_DATA_DIRECTORY的RVA
ULONG_PTR GetDataDirectoryRVA (PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry)
{
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	return pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].VirtualAddress;
}
//获取特定IMAGE_DATA_DIRECTORY的Size
ULONG_PTR GetDataDirectorySize (PIMAGE_DOS_HEADER pDosHeader, WORD	wDirectoryEntry)
{
	PIMAGE_NT_HEADERS	pNtHeader = GetNtHeader (pDosHeader);
	return pNtHeader->OptionalHeader.DataDirectory[wDirectoryEntry].Size;
}


//计算添加PointerToRawData和VirtualAddress
BOOL	CalcSectionTableAddress (PIMAGE_DOS_HEADER pDosHeader, PDWORD pdwStartVirtualAddress, PDWORD pdwStartFileAddress)
{
	PIMAGE_SECTION_HEADER pLastSectionHeader = NULL;
	PEALIGNMENT pPeAlignment = { 0 };
	//获取最后一个段的参数
	if ( pZero != NULL ) {
		pLastSectionHeader = (PIMAGE_SECTION_HEADER)( (ULONG_PTR)pZero - sizeof (IMAGE_SECTION_HEADER) );
		GetAlignment (pDosHeader, &pPeAlignment);
	}
	else {
		DEBUG_INFO ("[-]识别最后一个节表失败\n");
		return FALSE;
	}
	//计算该填充的值
	*pdwStartVirtualAddress = GetStartAddress (pPeAlignment.SectionAlignment, pLastSectionHeader->Misc.VirtualSize, pLastSectionHeader->VirtualAddress);
	*pdwStartFileAddress = GetStartAddress (pPeAlignment.FileAlignment, pLastSectionHeader->SizeOfRawData, pLastSectionHeader->PointerToRawData);

	return TRUE;
}


//扩展内存
PBYTE	StretchFileToMemory (PIMAGE_DOS_HEADER pDosHeader, PDWORD pFileSize)
{
	//传入的是 硬盘中文件的映射
	PBYTE	pMemory = NULL;
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	DWORD	dwSizeOfImage = *pFileSize = pNtHeader->OptionalHeader.SizeOfImage;
	DWORD	dwNumberOfSection = GetNumberOfSection (pDosHeader);

	pMemory = VirtualAlloc (NULL, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	ZeroMemory (pMemory, dwSizeOfImage);

	if ( pMemory == NULL ) {
		DEBUG_INFO ("[-]申请空间失败\n");
		return NULL;
	}

	//拷贝整个PE头
	CopyHeader (pMemory, pDosHeader);
	//拷贝区块
	if ( !CopyAllSection (pMemory, pDosHeader, dwSizeOfImage) ) {
		VirtualFree (pMemory, 0, MEM_RELEASE);
		return NULL;
	}

	return pMemory;

}

//拷贝整个PE头
VOID CopyHeader (LPVOID	pDst, PIMAGE_DOS_HEADER	pDosHeader)
{
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader (pDosHeader);
	DWORD	dwSizeOfHeader = pNtHeader->OptionalHeader.SizeOfHeaders;
	//CopyMemory(pDst, pDosHeader, dwSizeOfHeader);
	while ( dwSizeOfHeader-- )
		*( (BYTE*)pDst )++ = *( (BYTE*)pDosHeader )++;
}

//拷贝区块
BOOL CopyAllSection (LPVOID	pMemory, PIMAGE_DOS_HEADER	pFile, DWORD dwSizeOfImage)
{

	//获取SectionTable
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
			DEBUG_INFO ("[-]超越边界\n");
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
		DEBUG_INFO ("[-]拷贝导入表失败\n");
		bResult = FALSE;
	}
	else {
		pZero += dwImportTableSize - sizeof (IMAGE_IMPORT_DESCRIPTOR);
	}


	DWORD	dwSizeOfFuncName = strlen (pFuncName) + 1;
	DWORD	dwSizeOfDllName = strlen (pDllName) + 1;
	//追加导入表
	IMAGE_IMPORT_DESCRIPTOR NewImportDescriptor = { 0 };

	//定位增加的导入表
	PIMAGE_IMPORT_DESCRIPTOR	pNewImport = pZero;
	pZero = (PBYTE)( (ULONG_PTR)pNewImport + sizeof (IMAGE_IMPORT_DESCRIPTOR) );
	//追加8个字节的INT表8个字节的IAT表
	//IAT / INT->PIMAGE_THUNK_DATA -> IMAGE_IMPORT_BY_NAME
	//INT IAT 指针
	PIMAGE_THUNK_DATA pIATTable = (PIMAGE_THUNK_DATA)( (ULONG_PTR)pZero + sizeof (IMAGE_IMPORT_DESCRIPTOR) );
	PIMAGE_THUNK_DATA pINTTable = (PIMAGE_THUNK_DATA)( (ULONG_PTR)pIATTable + sizeof (IMAGE_THUNK_DATA) );

	//追加一个DLL名字
	PBYTE	pFileDllName = (PBYTE)( (ULONG_PTR)pIATTable + 2 * sizeof (PIMAGE_THUNK_DATA) );
	_memccpy (pFileDllName, pDllName, dwSizeOfDllName, dwSizeOfDllName);
	pNewImport->Name = OffsetToRVA (pDosHeader, (ULONG)pFileDllName - (ULONG)pDosHeader);

	//追加一个 IMAGE_IMPORT_BY_NAME结构, 前2个字节是0后面是函数名称字符串
	PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)( (ULONG_PTR)pFileDllName + dwSizeOfDllName );
	pImportByName->Hint = 0x01;
	_memccpy (pImportByName->Name, pFuncName, dwSizeOfFuncName, dwSizeOfFuncName);

	//将IMAGE_IMPORT_BY_NAME结构的RVA赋值给INT和IAT表中的第一项
	pNewImport->OriginalFirstThunk = OffsetToRVA (pDosHeader, (ULONG)pINTTable - (ULONG)pDosHeader);
	pNewImport->OriginalFirstThunk = 0;
	pNewImport->FirstThunk = OffsetToRVA (pDosHeader, (ULONG)pIATTable - (ULONG)pDosHeader);
	//pINTTable->u1.AddressOfData = pIATTable->u1.AddressOfData = OffsetToRVA(pDosHeader,(ULONG)pImportByName - (ULONG)pDosHeader);
	pIATTable->u1.AddressOfData = OffsetToRVA (pDosHeader, (ULONG)pImportByName - (ULONG)pDosHeader);

	//修正IMAGE_DATA_DIRECT0RY结构的 VirtualAddress和Sie
	DWORD	dwNewVirtualAddress = OffsetToRVA (pDosHeader, (ULONG)pImportTableHeader - (ULONG)pDosHeader);

	SetDataDirectoryRVA (pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT, dwNewVirtualAddress);
	SettDataDirectorySize (pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT, dwImportTableSize + sizeof (IMAGE_IMPORT_DESCRIPTOR));
	return bResult;
}

//Shellcode 处理导入表
//需要传入函数地址
VOID ShellCodeRepairImportTable (
	PIMAGE_DOS_HEADER pDosHeader, GETPROCADDRESS pGetProcAddress, LOADLIBRARY pLoadLibrary)
{
	//全部用ULONG_PTR好恶心，强转麻了
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	ULONG_PTR	uiRva = 0;

	//导入表相关
	ULONG_PTR	uiImportTable = 0;
	ULONG_PTR	uiImportINT = 0;
	ULONG_PTR	uiImportIAT = 0;
	ULONG_PTR	uiImportByName = 0;

	//DLL相关
	ULONG_PTR	uiLibraryAddr = 0;
	//DLL导出表
	ULONG_PTR	uiExportTable = 0;
	ULONG_PTR	uiExportEAT = 0;

	pNtHeader = GetNtHeader (pDosHeader);
	uiRva = GetDataDirectoryRVA (pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);

	if ( uiRva == 0 ) {
		DEBUG_INFO ("[+]没有导入表\n");
		return;
	}

	//指向导入表节表
	uiImportTable = (ULONG_PTR)pDosHeader + uiRva;

	//遍历导入表
	while ( ( (PIMAGE_IMPORT_DESCRIPTOR)uiImportTable )->Name ) {
		//载入名称指向的DLL

		uiLibraryAddr = (ULONG_PTR)pLoadLibrary ((LPCSTR)( (ULONG_PTR)pDosHeader + ( (PIMAGE_IMPORT_DESCRIPTOR)uiImportTable )->Name ));

		//获取导入表的INT表
		uiImportINT = (ULONG_PTR)pDosHeader + ( (PIMAGE_IMPORT_DESCRIPTOR)uiImportTable )->OriginalFirstThunk;

		//获取导入表的IAT表
		uiImportIAT = (ULONG_PTR)pDosHeader + ( (PIMAGE_IMPORT_DESCRIPTOR)uiImportTable )->FirstThunk;

		//使用名字进行获取，如果没有使用名字使用序号进行获取
		while ( DEREF(uiImportIAT) )
		{
			//if(IMAGE_SNAP_BY_ORDINAL((PIMAGE_THUNK_DATA)uiImportINT)->u1.Ordinal ){
			if ( uiImportIAT && ( (PIMAGE_THUNK_DATA)uiImportIAT )->u1.AddressOfData & IMAGE_ORDINAL_FLAG ) {
				//获取该DLL的导出表地址
				uiExportTable = uiLibraryAddr + (ULONG_PTR)GetDataDirectoryRVA((PIMAGE_DOS_HEADER)uiLibraryAddr, IMAGE_DIRECTORY_ENTRY_EXPORT);

				//获取地址表
				uiExportEAT = uiLibraryAddr + (ULONG_PTR)( ( (PIMAGE_EXPORT_DIRECTORY)uiExportTable )->AddressOfFunctions );

				//获取导入函数地址的RVA
				uiExportEAT += ( ( IMAGE_ORDINAL(( ( (PIMAGE_THUNK_DATA)uiImportINT )->u1.Ordinal ) - ( ( (PIMAGE_EXPORT_DIRECTORY)uiExportTable )->Base )) ) * sizeof(DWORD) );

				DEREF(uiImportIAT) = ( uiLibraryAddr + DEREF(uiExportEAT) );

			}
			else {
				//访问IMAGE_IMPORT_BY_NAME获取函数名字
				uiImportByName = ( (ULONG_PTR)pDosHeader + DEREF(uiImportIAT) );

				DEREF(uiImportIAT) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddr, (LPCSTR)( ( (PIMAGE_IMPORT_BY_NAME)uiImportByName ) )->Name);
			}
			uiImportIAT += sizeof(ULONG_PTR);
			if ( uiImportINT )
				uiImportINT += sizeof(ULONG_PTR);
		}

		//遍历下一个表
		uiImportTable += sizeof (IMAGE_IMPORT_DESCRIPTOR);
	}


}
//=================================================
//最大优化(优选大小) (/O1)
// 只适用于 __inline (/Ob1)
//=================================================


//ShellCode处理重定位
VOID	ShellCodeFixReloc(PIMAGE_DOS_HEADER	pMemory, PIMAGE_DOS_HEADER pDosHeader)
{
	//需要添加的差值
	LONG_PTR	uiValue = 0;

	//指向重定位更改的VA
	ULONG_PTR	uiMemVa = 0;

	//获取到的重定位表
	ULONG_PTR	uiReloc = 0;
	ULONG_PTR	uiRva = 0;
	ULONG_PTR	uiBlockNum = 0;
	ULONG_PTR	uiBlock = 0;

	//计算差值
	uiValue = (LONG_PTR)pMemory - GetNtHeader(pDosHeader)->OptionalHeader.ImageBase;
	if ( uiRva = (ULONG_PTR)GetDataDirectoryRVA(pMemory, IMAGE_DIRECTORY_ENTRY_BASERELOC) )
	{
		uiReloc = (ULONG_PTR)pMemory + uiRva;

		//遍历所有区块
		while ( ( (PIMAGE_BASE_RELOCATION)uiReloc )->SizeOfBlock ) 
		{
			//定位块开头
			uiMemVa = (ULONG_PTR)pMemory + (ULONG_PTR)( ( (PIMAGE_BASE_RELOCATION)uiReloc )->VirtualAddress );

			//获取块数量
			uiBlockNum = (ULONG_PTR)(( ( (PIMAGE_BASE_RELOCATION)uiReloc )->SizeOfBlock ) - sizeof(IMAGE_BASE_RELOCATION) / sizeof(IMAGE_RELOC));

			//定位一个块
			uiBlock = uiReloc + sizeof(IMAGE_BASE_RELOCATION);

			//VirtualAddress(1000) + Offset(420) = 1420(RVA)
			//再加上ImageBase
			
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


			//多个区块成线性排列
			uiReloc += (ULONG_PTR)( ( (PIMAGE_BASE_RELOCATION)uiReloc )->SizeOfBlock );
		}

	}
}

//ShellCode 搜寻未展开导出表函数
DWORD	GetFileExportFunctionOffset(PIMAGE_DOS_HEADER	pDosHeader, PCHAR pFuncName)
{

	ULONG_PTR uiRva = 0;
	DWORD dwCounter = 0;

	PIMAGE_EXPORT_DIRECTORY pExportDirect = NULL;
	PDWORD pEAT = NULL;
	PDWORD pENT = NULL;
	PWORD pEOT = NULL;
	//校验版本
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

	//指向文件偏移的导出表
	pExportDirect = (PIMAGE_EXPORT_DIRECTORY)( (ULONG_PTR)pDosHeader + RVAToOffset(pDosHeader, uiRva) );

	//指向EAT，DWORD数组
	pEAT = (PDWORD)( (ULONG_PTR)pDosHeader + RVAToOffset(pDosHeader, pExportDirect->AddressOfFunctions) );

	//指向ENT，DOWRD数组
	pENT = (PDWORD)( (ULONG_PTR)pDosHeader + RVAToOffset(pDosHeader, pExportDirect->AddressOfNames) );

	//指向EOT，WORD数组
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