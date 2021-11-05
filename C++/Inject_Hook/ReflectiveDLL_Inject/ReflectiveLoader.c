#include"ReflectiveLoader.h"
#include"GetFunction.h"

//#define _GLOBAL_DEBUG_INFO_

//Copy From https://github.com/stephenfewer/ReflectiveDLLInjection 

//通过intrinsic关键字，编译器将不会优化，不进行内联，直接调用函数
#pragma intrinsic(_ReturnAddress)

//__declspec(noinline) 不进行内联
//_ReturnAddress返回当前汇编命令执行地址
DECLSPEC_NOINLINE ULONG_PTR	ReturnFuncAddres(VOID)
{
	//Call _ReturnAddress
	//mov	[],rax -> rax=这一行的地址
	return (ULONG_PTR)_ReturnAddress( );
}


//定义定义参数
//此到处函数不能使用额外的API
#ifdef REFLECTIVELOADER_NO_PARAMETER
DLLEXPORT	ULONG_PTR	WINAPI ReflectiveLoader(VOID)
#else
//不定义参数
DLLEXPORT	ULONG_PTR	WINAPI ReflectiveLoader(LPVOID	lpParameter)
#endif // !REFLECTIVELOADER_NO_PARAMETER
{
	//__debugbreak( );
	//PE头部
	ULONG_PTR uiDosHeader;
	DWORD	dwSizeOfHeader;
	//获取Caller函数地址后,内存向上搜寻IMAGE_DOS_HEADER,定位文件位置
	ULONG_PTR uiBaseAddr;
	ULONG_PTR uiNtHeader;
	ULONG_PTR uiImageSize;
	ULONG_PTR uiEntryPoint;

	ULONG_PTR uiHeaderValue;

	ULONG_PTR dwSizeOfRawData;
	ULONG_PTR dwVirtualAddress;
	ULONG_PTR dwPointerToRawData;

	//定义函数指针
	VIRTUALALLOC pVirtualAlloc = NULL;
	GETPROCADDRESS	pGetProcAddress = NULL;
	LOADLIBRARY	pLoadLibrary = NULL;
	//用来刷新指令
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

	//step0 获取Dos头部	
	uiBaseAddr = ReturnFuncAddres( );
	while ( TRUE ) {
		////汇编"POP R10" = 0x4D5A，所以要做两步校验PE文件
		//if ( ( (PIMAGE_DOS_HEADER)uiBaseAddr )->e_magic == IMAGE_DOS_SIGNATURE ) {
		//	uiHeaderValue = ( (PIMAGE_DOS_HEADER)uiBaseAddr )->e_lfanew;

		//	if ( uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024 ) {
		//		uiBaseAddr += uiHeaderValue;
		//		// break if we have found a valid MZ/PE header
		//		if ( ( (PIMAGE_NT_HEADERS)uiBaseAddr )->Signature == IMAGE_NT_SIGNATURE )
		//			break;
		//	}
		//}
		//使用不了 编译链接后出现问题
		if ( IsPE((PIMAGE_DOS_HEADER)uiBaseAddr) )
			break;
		uiBaseAddr--;
	}
	uiDosHeader = uiBaseAddr;

	//step1 获取shellcode处理所需的必要函数
	pVirtualAlloc = GetFunction(KERNEL32DLL_HASH, VIRTUALALLOC_HASH);
	pGetProcAddress = GetFunction(KERNEL32DLL_HASH, GETPROCADDRESS_HASH);
	pLoadLibrary = GetFunction(KERNEL32DLL_HASH, LOADLIBRARYA_HASH);
	pNtFlushInstructionCache = GetFunction(NTDLLDLL_HASH, NTFLUSHINSTRUCTIONCACHE_HASH);
	//step1 申请空间，拷贝头部
	//获取Nt头部

	uiNtHeader = (ULONG_PTR)GetNtHeader((PIMAGE_DOS_HEADER)uiDosHeader);
	uiImageSize = (ULONG_PTR)( (PIMAGE_NT_HEADERS)uiNtHeader )->OptionalHeader.SizeOfImage;

	//申请空间
	uiBaseAddr = (ULONG_PTR)pVirtualAlloc(NULL, uiImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//拷贝
	//CopyHeader((LPVOID)uiBaseAddr, uiDosHeader);

	dwSizeOfHeader = (DWORD)( ( (PIMAGE_NT_HEADERS)uiNtHeader )->OptionalHeader.SizeOfHeaders );
	//CopyMemory(pDst, pDosHeader, dwSizeOfHeader);
	while ( dwSizeOfHeader-- )
		*( (BYTE*)uiBaseAddr )++ = *( (BYTE*)uiDosHeader )++;

	//step3 拷贝区块
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


	//step4 处理导入表
	ShellCodeRepairImportTable((PIMAGE_DOS_HEADER)uiBaseAddr, pGetProcAddress, pLoadLibrary);

	//step5 处理重定位表
	ShellCodeFixReloc((PIMAGE_DOS_HEADER)uiBaseAddr, (PIMAGE_DOS_HEADER)uiDosHeader);



	//step6 刷新指针
	pNtFlushInstructionCache((HANDLE)( uiBaseAddr - 1 ), NULL, 0);


	//step7 调用EntryPoint
	uiEntryPoint = uiBaseAddr + (ULONG_PTR)( ( (PIMAGE_NT_HEADERS)uiNtHeader )->OptionalHeader.AddressOfEntryPoint );
#ifdef REFLECTIVELOADER_NO_PARAMETER
	((DLLMAIN)uiEntryPoint)( (HINSTANCE)uiBaseAddr, DLL_PROCESS_ATTACH, NULL );
#else
	( (DLLMAIN)uiEntryPoint )( (HINSTANCE)uiBaseAddr, DLL_PROCESS_ATTACH, lpParameter );
#endif // REFLECTIVELOADER_NO_PARAMETER


	//step8 Return DllMain	Address
	return	uiEntryPoint;
}