// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include"pch.h"
#include<cstdio>
#include<windows.h>
#include<process.h>
#include<winsock.h>
#include"dll1.h"

#pragma comment(lib, "Ws2_32.lib")






extern "C" DllExport  LRESULT CALLBACK CallWndProc(
    _In_ int    nCode,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
) {
    //MessageBoxA(NULL, lpStr, NULL, NULL);
    HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, SendMsg, (void*)lpStr, 0, NULL);
    if (hThread != 0) {
        //printf("创建线程成功！\n");
        CloseHandle(hThread);
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);

}


unsigned int __stdcall SendMsg(PVOID pParam){
    WSADATA wsaData;
    LPSTR lpStr =(LPSTR) pParam;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    if (HIBYTE(wsaData.wVersion) != 2 || LOBYTE(wsaData.wVersion) != 2)
    {
        printf("请求版本失败！");
        return 0;
    }
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKADDR_IN addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(10086);
    int RET = connect(clientSocket, (sockaddr*)&addr, sizeof addr);
    if (RET != SOCKET_ERROR) {
        RET = send(clientSocket, lpStr, strlen(lpStr), NULL);
    }
    closesocket(clientSocket);
    WSACleanup();
    _endthreadex(0);
    return 0;
}

extern "C" DllExport  BOOL SetHook() {
    hHook = SetWindowsHookEx(WH_GETMESSAGE, CallWndProc, g_hInstance, 0);
    //int a = GetLastError();
    //printf("%s\n", a);
    if (hHook != NULL) {
        return TRUE;
    }
    return FALSE;
}

extern "C" DllExport   void UnHook() {
    UnhookWindowsHookEx(hHook);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        g_hInstance = hModule;
        GetModuleFileNameA(NULL, (LPSTR)lpFileName, BufSize);
        dwProcessid = GetCurrentProcessId();
        sprintf_s(lpStr, 512, "已载入进程：%d,文件名：%s", dwProcessid, lpFileName);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


