#include"ReflectiveLoader.h"
#include"GetFunction.h"

//#define _GLOBAL_DEBUG_INFO_

//Copy From https://github.com/stephenfewer/ReflectiveDLLInjection 

//ͨ��intrinsic�ؼ��֣��������������Ż���������������ֱ�ӵ��ú���
#pragma intrinsic(_ReturnAddress)

//__declspec(noinline) ����������
//_ReturnAddress���ص�ǰ�������ִ�е�ַ
DECLSPEC_NOINLINE ULONG_PTR	ReturnFuncAddres(VOID)
{
	//Call _ReturnAddress
	//mov	[],rax -> rax=��һ�еĵ�ַ
	return (ULONG_PTR)_ReturnAddress( );
}


//���嶨�����
//�˵�����������ʹ�ö����API
#ifdef REFLECTIVELOADER_NO_PARAMETER
DLLEXPORT	ULONG_PTR	WINAPI ReflectiveLoader(VOID)
#else
//���������
DLLEXPORT	ULONG_PTR	WINAPI ReflectiveLoader(LPVOID	lpParameter)
#endif // !REFLECTIVELOADER_NO_PARAMETER
{
	//__debugbreak( );
	//PEͷ��
	ULONG_PTR uiDosHeader;
	DWORD	dwSizeOfHeader;
	//��ȡCaller������ַ��,�ڴ�������ѰIMAGE_DOS_HEADER,��λ�ļ�λ��
	ULONG_PTR uiBaseAddr;
	ULONG_PTR uiNtHeader;
	ULONG_PTR uiImageSize;
	ULONG_PTR uiEntryPoint;

	ULONG_PTR uiHeaderValue;

	ULONG_PTR dwSizeOfRawData;
	ULONG_PTR dwVirtualAddress;
	ULONG_PTR dwPointerToRawData;

	//���庯��ָ��
	VIRTUALALLOC pVirtualAlloc = NULL;
	GETPROCADDRESS	pGetProcAddress = NULL;
	LOADLIBRARY	pLoadLibrary = NULL;
	//����ˢ��ָ��
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

	//step0 ��ȡDosͷ��	
	uiBaseAddr = ReturnFuncAddres( );
	while ( TRUE ) {
		////���"POP R10" = 0x4D5A������Ҫ������У��PE�ļ�
		//if ( ( (PIMAGE_DOS_HEADER)uiBaseAddr )->e_magic == IMAGE_DOS_SIGNATURE ) {
		//	uiHeaderValue = ( (PIMAGE_DOS_HEADER)uiBaseAddr )->e_lfanew;

		//	if ( uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024 ) {
		//		uiBaseAddr += uiHeaderValue;
		//		// break if we have found a valid MZ/PE header
		//		if ( ( (PIMAGE_NT_HEADERS)uiBaseAddr )->Signature == IMAGE_NT_SIGNATURE )
		//			break;
		//	}
		//}
		//ʹ�ò��� �������Ӻ��������
		if ( IsPE((PIMAGE_DOS_HEADER)uiBaseAddr) )
			break;
		uiBaseAddr--;
	}
	uiDosHeader = uiBaseAddr;

	//step1 ��ȡshellcode��������ı�Ҫ����
	pVirtualAlloc = GetFunction(KERNEL32DLL_HASH, VIRTUALALLOC_HASH);
	pGetProcAddress = GetFunction(KERNEL32DLL_HASH, GETPROCADDRESS_HASH);
	pLoadLibrary = GetFunction(KERNEL32DLL_HASH, LOADLIBRARYA_HASH);
	pNtFlushInstructionCache = GetFunction(NTDLLDLL_HASH, NTFLUSHINSTRUCTIONCACHE_HASH);
	//step1 ����ռ䣬����ͷ��
	//��ȡNtͷ��

	uiNtHeader = (ULONG_PTR)GetNtHeader((PIMAGE_DOS_HEADER)uiDosHeader);
	uiImageSize = (ULONG_PTR)( (PIMAGE_NT_HEADERS)uiNtHeader )->OptionalHeader.SizeOfImage;

	//����ռ�
	uiBaseAddr = (ULONG_PTR)pVirtualAlloc(NULL, uiImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//����
	//CopyHeader((LPVOID)uiBaseAddr, uiDosHeader);

	dwSizeOfHeader = (DWORD)( ( (PIMAGE_NT_HEADERS)uiNtHeader )->OptionalHeader.SizeOfHeaders );
	//CopyMemory(pDst, pDosHeader, dwSizeOfHeader);
	while ( dwSizeOfHeader-- )
		*( (BYTE*)uiBaseAddr )++ = *( (BYTE*)uiDosHeader )++;

	//step3 ��������
	//CopyAllSection((LPVOID)uiBaseAddr, (PIMAGE_DOS_HEADER)uiDosHeader, uiImageSize);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION ((PIMAGE_NT_HEADERS)uiNtHeader);
	PIMAGE_SECTION_HEADER pFirstSection = pSection;
	DWORD dwNumberOfSection = ( (PIMAGE_NT_HEADERS)uiNtHeader )->FileHeader.NumberOfSections;

	while ( dwNumberOfSection-- )
	{

		// uiValueB is the VA for this section
		dwVirtualAddress = ( uiBaseAddr + pFirstSection->VirtualAddress );

		// uiValueC if the VA for this sections data
		dwPointerToRawData = ( uiDosHeader + pFirstSection->PointerToRawData );

		// copy the section over
		dwSizeOfRawData = (pFirstSection->SizeOfRawData) -1;
			//while ( --dwSizeOfRawData )
			//	*( (BYTE*)dwVirtualAddress )++ = *( (BYTE*)dwPointerToRawData )++;
		while ( dwSizeOfRawData-- )
			*(BYTE*)dwVirtualAddress++ = *(BYTE*)dwPointerToRawData++;

		// get the VA of the next section
		pFirstSection++;
	}

	//for ( int i = 0; i < dwNumberOfSection; i++ ) {
	//	ULONG_PTR dwVirtualAddress = pSection->VirtualAddress;
	//	ULONG_PTR dwSizeOfRawData = pSection->SizeOfRawData;
	//	ULONG_PTR dwPointerToRawData = pSection->PointerToRawData;

	//	LPVOID lpRawOfData = (LPVOID)( (ULONG_PTR)uiDosHeader + dwPointerToRawData );
	//	LPVOID lpMemory = (LPVOID)( (ULONG_PTR)uiBaseAddr + dwVirtualAddress);
	//	//CopyMemory(lpMemory, lpRawOfData, dwSizeOfRawData);
	//	while ( dwSizeOfRawData-- )
	//		*( (BYTE*)lpMemory )++ = *( (BYTE*)lpRawOfData )++;
	//	pSection++;
	//}


	//step4 �������
	ShellCodeRepairImportTable((PIMAGE_DOS_HEADER)uiBaseAddr, pGetProcAddress, pLoadLibrary);

	//step5 �����ض�λ��
	ShellCodeFixReloc((PIMAGE_DOS_HEADER)uiBaseAddr, (PIMAGE_DOS_HEADER)uiDosHeader);



	//step6 ˢ��ָ��
	pNtFlushInstructionCache((HANDLE)( uiBaseAddr - 1 ), NULL, 0);


	//step7 ����EntryPoint
	uiEntryPoint = uiBaseAddr + (ULONG_PTR)( ( (PIMAGE_NT_HEADERS)uiNtHeader )->OptionalHeader.AddressOfEntryPoint );
#ifdef REFLECTIVELOADER_NO_PARAMETER
	((DLLMAIN)uiEntryPoint)( (HINSTANCE)uiBaseAddr, DLL_PROCESS_ATTACH, NULL );
#else
	( (DLLMAIN)uiEntryPoint )( (HINSTANCE)uiBaseAddr, DLL_PROCESS_ATTACH, lpParameter );
#endif // REFLECTIVELOADER_NO_PARAMETER


	//step8 Return DllMain	Address
	return	uiEntryPoint;
}