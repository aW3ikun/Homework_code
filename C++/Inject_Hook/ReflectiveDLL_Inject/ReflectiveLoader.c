#include"ReflectiveLoader.h"
#include"GetFunction.h"

//����DllMain�������
#define	REFLECTIVELOADER_NO_PARAMETER

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

	//PEͷ��
	ULONG_PTR uiDosHeader;

	//��ȡCaller������ַ��,�ڴ�������ѰIMAGE_DOS_HEADER,��λ�ļ�λ��
	ULONG_PTR uiBaseAddr;
	ULONG_PTR uiNtHeader;
	ULONG_PTR uiImageSize;
	ULONG_PTR uiEntryPoint;

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
		//if (((PIMAGE_DOS_HEADER)uiFuncAddr)->e_magic == IMAGE_DOS_SIGNATURE) {
		//	uiHeaderValue = ((PIMAGE_DOS_HEADER)uiFuncAddr)->e_lfanew;

		//	if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024) {
		//		uiHeaderValue += uiFuncAddr;
		//		// break if we have found a valid MZ/PE header
		//		if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
		//			break;
		//}
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
	uiBaseAddr = (ULONG_PTR)pVirtualAlloc(NULL, ( (PIMAGE_NT_HEADERS)uiDosHeader )->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//����
	CopyHeader((LPVOID)uiBaseAddr, uiDosHeader);

	//step3 ��������
	CopyAllSection((LPVOID)uiBaseAddr, (PIMAGE_DOS_HEADER)uiDosHeader, uiImageSize);

	//step4 �������
	ShellCodeRepairImportTable((PIMAGE_DOS_HEADER)uiBaseAddr, pGetProcAddress, pLoadLibrary);

	//step5 �����ض�λ��
	ShellCodeFixReloc((PIMAGE_DOS_HEADER)uiBaseAddr, (PIMAGE_DOS_HEADER)uiDosHeader);



	//step6 ˢ��ָ��
	pNtFlushInstructionCache((HANDLE)( uiBaseAddr - 1 ), NULL, 0);


	//step7 ����EntryPoint
	uiEntryPoint = uiBaseAddr + (ULONG_PTR)GetNtHeader(uiBaseAddr)->OptionalHeader.AddressOfEntryPoint;
#ifdef REFLECTIVELOADER_NO_PARAMETER
	((DLLMAIN)uiEntryPoint)( (HINSTANCE)uiBaseAddr, DLL_PROCESS_ATTACH, NULL );
#else
	( (DLLMAIN)uiEntryPoint )( (HINSTANCE)uiBaseAddr, DLL_PROCESS_ATTACH, lpParameter );
#endif // REFLECTIVELOADER_NO_PARAMETER


	//step8 Return DllMain	Address
	return	uiEntryPoint;
}