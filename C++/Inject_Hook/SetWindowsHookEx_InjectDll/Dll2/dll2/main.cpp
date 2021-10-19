// dllmain.cpp : 定义 DLL 应用程序的入口点。

#include"dll2.h"
#pragma comment(linker,"/export:SetHook=Dll2.SetHook")
#pragma comment(linker,"/export:UnHook=Dll2.UnHook")
#pragma comment(linker,"/export:CallWndProc=Dll2.CallWndProc")

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
        MessageBox(NULL, L"DLL2 Load", NULL, MB_OK);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


