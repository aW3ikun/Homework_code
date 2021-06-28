#include<stdint.h>
#include<cstdio>
#include<windows.h>

#pragma comment(linker, "/INCLUDE:__tls_used")

void print_consle(char* msg) {
	HANDLE hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	WriteConsoleA(hConsoleOutput, msg, strlen(msg), NULL, NULL);
}
void NTAPI tls_callback0(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
	char msg[80] = { 0 };
	wsprintfA(msg, "tls_callback0 DllHandle: %x, Reason: %d\n", DllHandle, Reason);
	print_consle(msg);
}
void NTAPI tls_callback1(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
	char msg[80] = { 0 };
	wsprintfA(msg, "tls_callback1 DllHandle: %x, Reason: %d\n", DllHandle, Reason);
	print_consle(msg);
}
void NTAPI tls_callback2(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
	char msg[80] = { 0 };
	wsprintfA(msg, "tls_callback2 DllHandle: %x, Reason: %d\n", DllHandle, Reason);
	print_consle(msg);
}
void NTAPI tls_callback3(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
	char msg[80] = { 0 };
	wsprintfA(msg, "tls_callback3 DllHandle: %x, Reason: %d\n", DllHandle, Reason);
	print_consle(msg);
}
//Second
#pragma data_seg(".CRT$XLX")
PIMAGE_TLS_CALLBACK p_thread_callback[] = { tls_callback0 ,tls_callback1};
#pragma data_seg()

//First 
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback1[] = { tls_callback2 ,tls_callback3 };
#pragma data_seg()

DWORD WINAPI ThreadProc(LPVOID lParam) {
	printf("thread start\n");
	printf("thread end\n");
	return 0;
}
int main(int argc, char* argv[]) {
	printf("main start\n");

	HANDLE hThread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
	WaitForSingleObject(hThread, 60 * 1000);
	CloseHandle(hThread);

	printf("main end\n");
	system("pause");
}