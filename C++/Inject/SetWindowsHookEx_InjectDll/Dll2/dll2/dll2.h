#pragma once
#include<Windows.h>

#define DllExport   __declspec( dllexport )
extern "C" DllExport  LRESULT CALLBACK CallWndProc(
    _In_ int    nCode,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);
extern "C" DllExport  BOOL SetHook();
extern "C" DllExport   void UnHook();

