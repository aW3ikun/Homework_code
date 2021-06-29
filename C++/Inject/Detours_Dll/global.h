#pragma once
#define BUFSIZE 512
#include<process.h>
#include<Windows.h>
#include<cstdio>
#include<stdlib.h>
#include<winhttp.h>
#include <map> 
#include <vector>
#include<iostream>
using namespace std;
#include"detours/detours.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"detours\\detourslib_X86\\detours.lib")
//#pragma comment(lib,"detours\\detourslib_X64\\detours.lib")


#pragma comment(linker, "/INCLUDE:__tls_used")
static __declspec(thread) TCHAR lpMessage[BUFSIZE] = { 0 };

unsigned int WINAPI ThreadProc(LPVOID pParam);
BOOL Log(LPWSTR lpszStr);

static struct DllFunction
{
	string DllName;
	vector<std::string> vFunction;
}dllFunc;

