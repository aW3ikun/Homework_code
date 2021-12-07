#pragma once
#include<Windows.h>
#include<stdio.h>
#include<assert.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DLL_QUERY_HMODULE		6

//替换函数名  
#ifdef _DEBUG  
#define DEBUG_INFO(format, ...) printf("Function:%s\n%s\n", __FUNCTION__,format);
#define DEBUG_ERROR(format)  printf("File:%s, Line:%d, Function:%s\n%s\tError_Code: %d\n", __FILE__, __LINE__, __FUNCTION__,format,GetLastError( ));
//#define DEBUG_INFO(format, ...) NULL;
#else  
//#define DEBUG_INFO(format, ...) printf("%s\n",format);
#define DEBUG_INFO(format, ...) NULL
#define DEBUG_ERROR(format) NULL;

#endif  

typedef ULONG_PTR (WINAPI* REFLECTIVELOADER)( VOID );
typedef BOOL (WINAPI* DLLMAIN)( HINSTANCE, DWORD, LPVOID );


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
//使用堆Heap读取文件
LPVOID	HeapReadFile(PCHAR pFileName);
//写文件
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD FileSize,  PCHAR pFileName);
//拷贝数据到文件末尾
VOID	MyCopyBufferToFileEnd(PBYTE	pFileBuffer, DWORD	dwSectionSize,DWORD dwFileSize, PBYTE pCode);
////获取文件大小
//ULONG_PTR MyGetFileSize(HANDLE hFile);

//处理文件名
PCHAR AddFileName(PCHAR pFileName);


//为OpenProcess提升权限 
//“SeDebugPrivilege”表示该特权可用于调试及更改其它进程的内存
BOOL AdvancePrivilege2Debug( );


//获取反射注入的函数地址并进行调用
HANDLE	WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter, PCHAR pFuncName);

//打开进程 创建远程线程
//反射注入接口
//进程ID，DLL数据，DLL大小，导出表函数名，参数
VOID InjectDLL(DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength, PCHAR pFuncName, LPVOID lpParameter,BOOL bFlag);

//调用DLL 获取DLL的句柄
HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength, PCHAR pFuncName);
