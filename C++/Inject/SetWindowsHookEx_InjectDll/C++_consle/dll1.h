#pragma once
#include<Windows.h>

#define DllExport   __declspec( dllexport )
#define BufSize 512
unsigned int __stdcall SendMsg(PVOID pParam);
extern "C" DllExport  LRESULT CALLBACK CallWndProc(
    _In_ int    nCode,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);
extern "C" DllExport  BOOL SetHook();
extern "C" DllExport   void UnHook();

