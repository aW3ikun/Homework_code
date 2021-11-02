#include"ReflectiveLoader.h"
//不向DllMain传入参数
#define	REFLECTIVELOADER_NO_PARAMETER

//Copy From https://github.com/stephenfewer/ReflectiveDLLInjection 

//通过intrinsic关键字，编译器将不会优化，不进行内联，直接调用函数
#pragma intrinsic(_ReturnAddress)

//__declspec(noinline) 不进行内联
//_ReturnAddress返回当前汇编命令执行地址
DECLSPEC_NOINLINE ULONG_PTR	ReturnFuncAddres (VOID){
	//Call _ReturnAddress
	//mov	[],rax -> rax=这一行的地址
	return (ULONG_PTR)_ReturnAddress();
}


//定义定义参数
#ifdef REFLECTIVELOADER_NO_PARAMETER
DLLEXPORT	ULONG_PTR	WINAPI ReflectiveLoader(VOID)
#else
//不定义参数
DLLEXPORT	ULONG_PTR	WINAPI ReflectiveLoader(LPVOID	lpParameter)
#endif // !REFLECTIVELOADER_NO_PARAMETER
{

	ULONG_PTR uiDosHeader;

	//获取Caller函数地址后,内存向上搜寻IMAGE_DOS_HEADER,定位文件位置
	ULONG_PTR uiCallerAddr;
	//step0 获取Dos头部	
	

	

	//step8 Return DllMain	Address
	return	uiBaseAddr;
}