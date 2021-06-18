#pragma once
#include<Windows.h>
#ifndef   DLL1_H       //如果没有定义这个宏  
#define   DLL1_H 
#define DllExport   __declspec( dllexport )
#define BufSize 512
unsigned int __stdcall SendMsg(PVOID pParam);
extern "C" DllExport  LRESULT CALLBACK CallWndProc(
    _In_ int    nCode,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);
extern "C" DllExport  BOOL SetHook();
extern "C" DllExport   void UnHook();

HHOOK hHook;
HMODULE g_hInstance;
DWORD dwProcessid;
CHAR lpFileName[BufSize];
CHAR lpStr[BufSize];
#endif  