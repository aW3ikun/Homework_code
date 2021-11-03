#include"ReflectiveLoader.h"
#include"GetFunction.h"

//不向DllMain传入参数
#define	REFLECTIVELOADER_NO_PARAMETER

//Copy From https://github.com/stephenfewer/ReflectiveDLLInjection 

//通过intrinsic关键字，编译器将不会优化，不进行内联，直接调用函数
#pragma intrinsic(_ReturnAddress)

//__declspec(noinline) 不进行内联
//_ReturnAddress返回当前汇编命令执行地址
DECLSPEC_NOINLINE ULONG_PTR	ReturnFuncAddres(VOID) {
	//Call _ReturnAddress
	//mov	[],rax -> rax=这一行的地址
	return (ULONG_PTR)_ReturnAddress();
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

	//PE头部
	ULONG_PTR uiDosHeader;

	//获取Caller函数地址后,内存向上搜寻IMAGE_DOS_HEADER,定位文件位置
	ULONG_PTR uiBaseAddr;

	//定义函数指针
	VIRTUALALLOC pVirtualAlloc = NULL;
	GETPROCADDRESS	pGetProcAddress = NULL;
	LOADLIBRARY	pLoadLibrary = NULL;

	//step0 获取Dos头部	
	uiBaseAddr = ReturnFuncAddres();
	while (TRUE) {
		////汇编"POP R10" = 0x4D5A，所以要做两步校验PE文件
		//if (((PIMAGE_DOS_HEADER)uiFuncAddr)->e_magic == IMAGE_DOS_SIGNATURE) {
		//	uiHeaderValue = ((PIMAGE_DOS_HEADER)uiFuncAddr)->e_lfanew;

		//	if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024) {
		//		uiHeaderValue += uiFuncAddr;
		//		// break if we have found a valid MZ/PE header
		//		if (((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE)
		//			break;
		//}
		if (IsPE((PIMAGE_DOS_HEADER)uiBaseAddr))
			break;
		uiBaseAddr--;
	}
	uiDosHeader = uiBaseAddr;

	//step1 获取shellcode处理所需的必要函数
	pVirtualAlloc = GetFunction(KERNEL32DLL_HASH, VIRTUALALLOC_HASH);
	pGetProcAddress = GetFunction(KERNEL32DLL_HASH, GETPROCADDRESS_HASH);
	pLoadLibrary = GetFunction(KERNEL32DLL_HASH, LOADLIBRARYA_HASH);

	//step1 申请空间，拷贝头部
	uiBaseAddr = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiDosHeader)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	CopyHeader((LPVOID)uiBaseAddr, uiDosHeader);

	//step8 Return DllMain	Address
	//return	uiBaseAddr;
	return 0;
}