#pragma once
#include<Windows.h>
#include<stdio.h>

extern LONGLONG LongFileSize;

//��Ҫ�ӿڵ���
BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);

//��80�ֽڿռ����������,��һ�������������
BOOL AddOneSectionNormal(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);

//��PEͷ��ǰ
BOOL	AddSectionAdvanceNtHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize);



//�ļ�����
//���ļ�
PBYTE	MyReadFile(PCHAR pFileName);
//д�ļ�
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName);
//��ȡ�ļ���С
ULONG_PTR MyGetFileSize(HANDLE hFile);

//�����ļ���
PCHAR AddFileName(PCHAR pFileName);