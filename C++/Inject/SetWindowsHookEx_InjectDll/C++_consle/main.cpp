
#include<cstdio>
//#include<windows.h>
#include<process.h>
#include"dll1.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib,".\\Debug\\Dll1.lib")
#define BUFSIZE 512
HHOOK hHook2;

typedef BOOL(WINAPI* pMyFunc)(VOID);

unsigned int __stdcall ThreadProc(PVOID pParam) {
	CHAR buf[512] = { 0 };
	SOCKET acceptSocket = (SOCKET)pParam;
	recv(acceptSocket, buf, BUFSIZE, 0);
	printf("%s\n", buf);
	closesocket(acceptSocket);
	_endthreadex(0);
	return 0;
}

unsigned int __stdcall CancelHook(PVOID pParam) {
	pMyFunc UnHook = (pMyFunc)pParam;
	int Ret = MessageBoxA(NULL, "点击取消Hook", "取消Hook", MB_OK);
	if (Ret == IDOK)
		UnHook();
	system("pause");
	exit(0);
	_endthreadex(0);
	return 0;
}




int main(int argc, char* argv[]) {
	//MessageBoxA(NULL, "Main", NULL, MB_OK);
	//HMODULE hLib = LoadLibraryA("Dll1.dll");

	//if (hLib != NULL) {
		//pMyFunc SetHook = (pMyFunc)GetProcAddress(hLib, "SetHook");
		//pMyFunc UnHook = (pMyFunc)GetProcAddress(hLib, "UnHook");
		bool bSuccess = SetHook();
		if (bSuccess == TRUE)
			printf("[+]Hook Success! \n");
		else {
			printf("[-]Hook Failed! \n");
			return -1;
		}

		//网络连接
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);

		if (HIBYTE(wsaData.wVersion) != 2 || LOBYTE(wsaData.wVersion) != 2)
		{
			printf("请求版本失败！");
			return -1;
		}
		HANDLE hThreadMsgBox = (HANDLE)_beginthreadex(NULL, 0, CancelHook, (void*)UnHook, 0, NULL);
		if (hThreadMsgBox != 0) {
			//printf("创建线程成功！\n");
			CloseHandle(hThreadMsgBox);
		}

		SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		SOCKADDR_IN addr = { 0 };
		addr.sin_family = AF_INET;
		addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
		addr.sin_port = htons(10086);

		int RET = bind(serverSocket, (sockaddr*)&addr, sizeof addr);
		if (RET != SOCKET_ERROR) {
			printf("绑定成功！\n");
			while (TRUE) {
				//printf("正在监听！\n");
				RET = listen(serverSocket, SOMAXCONN);
				if (RET != SOCKET_ERROR) {
					SOCKET  AcceptSocket = accept(serverSocket, NULL, NULL);
					HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, ThreadProc, (void*)AcceptSocket, 0, NULL);
					if (hThread != 0) {
						//printf("创建线程成功！\n");
						CloseHandle(hThread);
					}
					else {
						printf("创建线程失败！\n");
					}
				}
				else {
					printf("监听失败！\n");
				}
			}
		}
		else {
			printf("绑定失败！\n");
		}

	//}
	//else {
	//	printf("[-]Load Failed! \n");
	//}

	system("pause");
	return 0;
}
