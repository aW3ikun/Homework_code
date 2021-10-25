#pragma once
#include<Windows.h>
#include<stdio.h>
#include<assert.h>


//替换函数名  
#ifdef _DEBUG  
#define DEBUG_INFO(format, ...) printf("File:%s, Line:%d, Function:%s\n%s\n", __FILE__, __LINE__, __FUNCTION__,format);
#else  
#define DEBUG_INFO(format, ...) NULL
#endif  

//宏前面加上##的作用在于：当可变参数的个数为0时，这里的## 起到把前面多余的","去掉的作用  



extern LONGLONG LongFileSize;

//主要接口调用
BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//有80字节空间就正常扩充,另一个函数添加数据
BOOL AddOneSectionNormal(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//将PE头提前
BOOL	AddSectionAdvanceNtHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//扩大一个节 最后一个节
BOOL	ExpandSection(DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//文件操作
//读文件
PBYTE	MyReadFile(PCHAR pFileName, PDWORD pFileSize,DWORD dwSectionSize);
//写文件
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD FileSize,  PCHAR pFileName);
//拷贝数据
VOID	MyCopyBuffer(PBYTE	pFileBuffer, DWORD	dwSectionSize,DWORD dwFileSize, PBYTE pCode);
////获取文件大小
//ULONG_PTR MyGetFileSize(HANDLE hFile);

//处理文件名
PCHAR AddFileName(PCHAR pFileName);