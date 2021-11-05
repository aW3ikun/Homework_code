#include"ReflectiveLoader.h"

//存取当前DLL的句柄
extern HINSTANCE hAppInstance;

BOOL WINAPI DllMain(
	HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{

	switch ( fdwReason ) {
		case DLL_QUERY_HMODULE:
			if ( lpReserved != NULL )
				*(HINSTANCE*)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			MessageBoxA(NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK);
			break;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;

}