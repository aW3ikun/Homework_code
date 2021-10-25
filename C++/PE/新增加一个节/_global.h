#pragma once
#include<Windows.h>
#include<stdio.h>
#include<assert.h>


//�滻������  
#ifdef _DEBUG  
#define DEBUG_INFO(format, ...) printf("File:%s, Line:%d, Function:%s\n%s\n", __FILE__, __LINE__, __FUNCTION__,format);
#else  
#define DEBUG_INFO(format, ...) NULL
#endif  

//��ǰ�����##���������ڣ����ɱ�����ĸ���Ϊ0ʱ�������## �𵽰�ǰ������","ȥ��������  



extern LONGLONG LongFileSize;

//��Ҫ�ӿڵ���
BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//��80�ֽڿռ����������,��һ�������������
BOOL AddOneSectionNormal(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//��PEͷ��ǰ
BOOL	AddSectionAdvanceNtHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//����һ���� ���һ����
BOOL	ExpandSection(DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//�ļ�����
//���ļ�
PBYTE	MyReadFile(PCHAR pFileName, PDWORD pFileSize,DWORD dwSectionSize);
//д�ļ�
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD FileSize,  PCHAR pFileName);
//��������
VOID	MyCopyBuffer(PBYTE	pFileBuffer, DWORD	dwSectionSize,DWORD dwFileSize, PBYTE pCode);
////��ȡ�ļ���С
//ULONG_PTR MyGetFileSize(HANDLE hFile);

//�����ļ���
PCHAR AddFileName(PCHAR pFileName);