#include"../ReflectiveLoader.h"

int main() {
	HMODULE hDll =  LoadLibraryA("ReflectiveDLL_Inject_x64.dll");
	FARPROC pFunc =  GetProcAddress(hDll, "ReflectiveLoader");
	if (pFunc != NULL) {
		pFunc();
	}
	return 0;

}