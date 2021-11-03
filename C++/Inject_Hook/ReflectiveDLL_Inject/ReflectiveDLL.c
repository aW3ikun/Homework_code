#include"ReflectiveLoader.h"


BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpReserved) {

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		//MessageBoxA(NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;

}