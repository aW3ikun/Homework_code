#include <windows.h>
#include<stdio.h>


#define DllExport   __declspec( dllexport )

DllExport   void  MyMessageBox() {
    MessageBoxA(NULL, "Hello DLL", "Hello DLL", MB_OK);
    //printf("Heello\n");
}

BOOL WINAPI DllMain(
    HINSTANCE const instance,  // handle to DLL module
    DWORD     const reason,    // reason for calling function
    LPVOID    const reserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        MyMessageBox();
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        break;
    }
    return TRUE;
}