// dllmain.cpp : 定义 DLL 应用程序的入口点。

#include<iostream>
#include"help.h"
#include"Hook.h"


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	DetoursMyHook *mydetour = new DetoursMyHook();
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {
		TCHAR lpTemp[BUFSIZE] = { 0 };
		if (GetModuleFileNameW(NULL, lpTemp, BUFSIZE)) {
			wsprintf(lpMessage,L"[+]Injected into %s \n", lpTemp);
			Log(lpMessage);
		}
		mydetour->InsertMap(Sum(), TRUE);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	{
		delete mydetour;
		break;
	}
		break;
	}
	return TRUE;
}

