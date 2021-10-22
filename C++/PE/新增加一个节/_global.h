#pragma once
#include<Windows.h>
#include<stdio.h>

extern LONGLONG LongFileSize;

//主要接口调用
BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//有80字节空间就正常扩充,另一个函数添加数据
BOOL AddOneSectionNormal(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//将PE头提前
BOOL	AddSectionAdvanceNtHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);



//文件操作
//读文件
PBYTE	MyReadFile(PCHAR pFileName);
//写文件
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);
//获取文件大小
ULONG_PTR MyGetFileSize(HANDLE hFile);

//处理文件名
PCHAR AddFileName(PCHAR pFileName);