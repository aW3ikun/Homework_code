#pragma once
#include<Windows.h>
#include<stdio.h>
#include<assert.h>


//�滻������  
#ifdef _DEBUG  
//#define DEBUG_INFO(format, ...) printf("File:%s, Line:%d, Function:%s\n%s\n", __FILE__, __LINE__, __FUNCTION__,format);
#define DEBUG_INFO(format, ...) NULL;
#else  
//#define DEBUG_INFO(format, ...) printf("%s\n",format);
#define DEBUG_INFO(format, ...) NULL;
#endif  


extern LONGLONG LongFileSize;
//���PE�Ͱ汾
BOOL checkPeAndBit(PIMAGE_DOS_HEADER pDosHeader);

//��Ҫ�ӿڵ���
BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//��80�ֽڿռ����������,��һ�������������
BOOL AddOneSectionNormal(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//��PEͷ��ǰ
BOOL	AddSectionAdvanceNtHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//����һ���� ���һ����
BOOL	ExpandSection(DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//����һ���ڣ�����Ӷ���ĵ����
BOOL	ExpandSectionToAddImportTable(PCHAR pFileName, PCHAR pDllName, PCHAR pFuncName);

//�ϲ���һ����
BOOL	MergeOneSection(PCHAR pFileName);

//�ļ�����
//���ļ�
PBYTE	MyReadFile(PCHAR pFileName, PDWORD pFileSize,DWORD dwSectionSize);
//д�ļ�
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD FileSize,  PCHAR pFileName);
//�������ݵ��ļ�ĩβ
VOID	MyCopyBufferToFileEnd(PBYTE	pFileBuffer, DWORD	dwSectionSize,DWORD dwFileSize, PBYTE pCode);
////��ȡ�ļ���С
//ULONG_PTR MyGetFileSize(HANDLE hFile);

//�����ļ���
PCHAR AddFileName(PCHAR pFileName);
