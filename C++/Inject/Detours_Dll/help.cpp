#include"help.h"



DetoursMyHook::DetoursMyHook(map<LPVOID, LPVOID>mapHook, BOOL bflag)
{
	bHook = FALSE;
	InsertMap(mapHook, bflag);
}

DetoursMyHook::DetoursMyHook()
{
	bHook = FALSE;
}
DetoursMyHook::~DetoursMyHook()
{
	UnHook();
}

VOID DetoursMyHook::SetHook()
{
	if (bHook == FALSE) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		//0x75c535b0
		map<LPVOID, LPVOID>::iterator iter;
		for (iter = mapHookFunc.begin(); iter != mapHookFunc.end(); ++iter) {
			if (DetourAttach(&(PVOID&)iter->first, iter->second) != NO_ERROR)
				break;
		}
		if (DetourTransactionCommit() == NO_ERROR) {
			bHook = TRUE;
		}
	}
}

VOID DetoursMyHook::UnHook()
{
	if (bHook == TRUE) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		map<LPVOID, LPVOID>::iterator iter;
		for (iter = mapHookFunc.begin(); iter != mapHookFunc.end(); ++iter) {
			DetourDetach(&(PVOID&)iter->first, iter->second);
		}
		if (DetourTransactionCommit() == NO_ERROR) {
			bHook = FALSE;
		}
	}
}


void DetoursMyHook::InsertMap(map<LPVOID, LPVOID> mapHook, BOOL bflag) {
	if (mapHook.size() != 0) {
		mapHookFunc.insert(mapHook.begin(), mapHook.end());
	}
	if (bflag == TRUE) {
		SetHook();
	}
}