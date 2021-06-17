// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include"../../demo/CmnHdr.h"
#include<stdlib.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:{
        char szBuf[MAX_PATH * 100] = { 0 };
        PBYTE pb = NULL;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQuery(pb, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            int nLen;
            char szModeName[MAX_PATH];

            if (mbi.State == MEM_FREE)
                mbi.AllocationBase = mbi.BaseAddress;
            if ((mbi.AllocationBase == hModule) ||
                (mbi.AllocationBase != mbi.BaseAddress) ||
                (mbi.AllocationBase == NULL))
                nLen = 0;
            else {
                nLen = GetModuleFileNameA((HMODULE)mbi.AllocationBase, szModeName, _countof(szModeName));
            }

            if (nLen > 0) {
                wsprintfA(strchr(szBuf, 0), "\n%p-%s", mbi.AllocationBase, szModeName);
            }
            pb += mbi.RegionSize;
        }
        chMB(&szBuf[1]);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

