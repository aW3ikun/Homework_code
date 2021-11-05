#include <Windows.h>
#include"../ReflectiveLoader.h"

int main(int argc, char* argv[])
{
#ifdef _WIN64
	//char* cpDllFile =  "reflective_dll.x64.dll";
	//char* cpDllFile = "ReflectiveDLL_Inject_x64.dll";
	char* cpDllFile  = "D:\\TEMP\\ReflectiveDLLInjection\\bin\\reflective_dll.x64.dll";
#else 
	char* cpDllFile = "reflective_dll.dll";

#endif
	DWORD dwProcessId = 0;
	DWORD	dwFileSize = 0;
	LPVOID	lpBuffer = NULL;

	if ( argc == 1 )
		dwProcessId = GetCurrentProcessId( );

	do
	{
		lpBuffer = HeapReadFile(cpDllFile,&dwFileSize);
		if ( !lpBuffer )
			break;

		if ( !AdvancePrivilege2Debug( ) ) {
			DEBUG_INFO("[-]	Advance	Privilege Failed");
			break;
		}

		char FuncName[] = "ReflectiveLoader";
		InjectDLL(dwProcessId, lpBuffer, dwFileSize, FuncName, NULL);


	} while ( 0 );

	if ( lpBuffer )
		HeapFree(GetProcessHeap( ), 0, lpBuffer);

	return 0;

}