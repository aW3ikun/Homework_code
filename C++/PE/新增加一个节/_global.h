#pragma once
#include<Windows.h>
#include<stdio.h>

extern LONGLONG LongFileSize;

//主要接口调用
BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//文件操作
//读文件
PBYTE	MyReadFile(PCHAR pFileName);
//写文件
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);
//获取文件大小
ULONG_PTR MyGetFileSize(HANDLE hFile);

//处理文件名
PCHAR AddFileName(PCHAR pFileName);