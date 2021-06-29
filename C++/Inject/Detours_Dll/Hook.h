#pragma once
#include"global.h"
#include <codecvt>
#include <locale>
#include<string>
static TCHAR lpTemp[BUFSIZE];
inline std::wstring to_wide_string(const std::string& input);
int WINAPI Newsend(SOCKET s, const char* buf, int len, int flags);
BOOL NewWriteFile(HANDLE hFile,LPCVOID lpBuffer,DWORD  nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped);
map<LPVOID, LPVOID> Sum();
map<LPVOID, LPVOID> GetFunc(DllFunction dllfunc, vector<LPVOID> newFunc);