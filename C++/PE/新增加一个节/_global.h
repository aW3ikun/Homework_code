#pragma once
#include<Windows.h>
#include<stdio.h>

extern LONGLONG LongFileSize;

//��Ҫ�ӿڵ���
BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//�ļ�����
//���ļ�
PBYTE	MyReadFile(PCHAR pFileName);
//д�ļ�
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);
//��ȡ�ļ���С
ULONG_PTR MyGetFileSize(HANDLE hFile);

//�����ļ���
PCHAR AddFileName(PCHAR pFileName);