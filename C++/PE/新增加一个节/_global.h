#pragma once
#include<Windows.h>
#include<stdio.h>
#include<assert.h>


//替换函数名  
#ifdef _DEBUG  
//#define DEBUG_INFO(format, ...) printf("File:%s, Line:%d, Function:%s\n%s\n", __FILE__, __LINE__, __FUNCTION__,format);
#define DEBUG_INFO(format, ...) NULL;
#else  
//#define DEBUG_INFO(format, ...) printf("%s\n",format);
#define DEBUG_INFO(format, ...) NULL;
#endif  


extern LONGLONG LongFileSize;
//检查PE和版本
BOOL checkPeAndBit(PIMAGE_DOS_HEADER pDosHeader);

//主要接口调用
BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//有80字节空间就正常扩充,另一个函数添加数据
BOOL AddOneSectionNormal(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//将PE头提前
BOOL	AddSectionAdvanceNtHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//扩大一个节 最后一个节
BOOL	ExpandSection(DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//扩大一个节，并添加额外的导入表
BOOL	ExpandSectionToAddImportTable(PCHAR pFileName, PCHAR pDllName, PCHAR pFuncName);

//合并成一个节
BOOL	MergeOneSection(PCHAR pFileName);

//文件操作
//读文件
PBYTE	MyReadFile(PCHAR pFileName, PDWORD pFileSize,DWORD dwSectionSize);
//写文件
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD FileSize,  PCHAR pFileName);
//拷贝数据到文件末尾
VOID	MyCopyBufferToFileEnd(PBYTE	pFileBuffer, DWORD	dwSectionSize,DWORD dwFileSize, PBYTE pCode);
////获取文件大小
//ULONG_PTR MyGetFileSize(HANDLE hFile);

//处理文件名
PCHAR AddFileName(PCHAR pFileName);
