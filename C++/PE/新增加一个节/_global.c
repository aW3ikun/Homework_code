#include"_global.h"
#include"pe.h"

//��ȡ�ļ���˳����չ��С���ڴ���
PBYTE	MyReadFile(PCHAR pFileName) {
	HANDLE hFile = CreateFileA(pFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	//int error = GetLastError();
	PBYTE	lpFile = NULL;
	PBYTE	lpFileEnd = NULL;
	DWORD dwBytesToRead = 0;
	DWORD dwBytesRead = 0;
	if (hFile != INVALID_HANDLE_VALUE) {
		//��ȡ�ļ���С
		if (LongFileSize = MyGetFileSize(hFile)) {
			//��ȡ���������ڴ��С
			dwBytesToRead = LongFileSize;
			lpFile = VirtualAlloc(NULL, LongFileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			if (lpFile != NULL) {
				lpFileEnd = lpFile;
				ZeroMemory(lpFile, LongFileSize);
				//ѭ�����ļ���ȷ�������������ļ�
				do {
					if (!ReadFile(hFile, lpFileEnd, dwBytesToRead, &dwBytesRead, NULL)) {
						int error = GetLastError();
						printf("[-]�ļ���ȡʧ��: %d\n", error);
						return NULL;
					}

					if (dwBytesRead == 0)
						break;
					dwBytesToRead -= dwBytesRead;
					lpFileEnd += dwBytesRead;
				} while (dwBytesToRead > 0);
			}
		}
		else {
			printf("[-]�ļ���С��ȡʧ��\n");
		}
		CloseHandle(hFile);
	}
	else {
		printf("[-]�ļ���ʧ��\n");
	}

	return lpFile;
}

//�ļ�д��,���ʣ������
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName) {
	DWORD dwBytesToWrite = LongFileSize;
	DWORD dwBytesWrite = 0;
	BOOL bResult = FALSE;
	//�����ļ���
	PCHAR NewFileName = AddFileName(pFileName);
	HANDLE hFile = CreateFileA(NewFileName, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (WriteFile(hFile, pFileBuffer, dwBytesToWrite, &dwBytesWrite, NULL)) {
		if (WriteFile(hFile, pCode, dwSectionSize, &dwBytesWrite, NULL)) {
			bResult = TRUE;
		}
	}

	if (NewFileName != NULL) {
		free(NewFileName);
	}

	if (bResult == FALSE) {
		printf("[-]�ļ�д��ʧ��\n");
	}
	return bResult;
}

/*
1. �ж����Ƿ����㹻�ռ䣬�������һ���ڱ�
SizeOfHeaders-(DOS+DOS STUB+NTͷ+�Ѵ��ڽڱ�) >=2���ڱ��С
����ſ����,���������Ҫ��NT_HEADERǰ��
2. ���������ڱ�����
3. ������ڱ�������һ�����ڱ���С��00
4. �޸�PEͷ�нڵ�����NumberOfSections
5. �޸�SizeOfImage�Ĵ�С
6. ����µĽڵ���������(�ڴ����)
7. �����½ڵ�����
Name
VirtualSize
VirtualAddress = ��һ��VirtualAddress + SizeOfRawData �����ڴ����
PointToRawData ������һ��  PointToRawData + SizeOfRawData �����ļ�����
SizeOfRawData = VirtualSize
*/

//��ȡ�ļ���С
ULONG_PTR MyGetFileSize(HANDLE hFile) {
	LARGE_INTEGER  piFileSize = { 0 };
	LONGLONG FileSize = 0;
	if (GetFileSizeEx(hFile, &piFileSize)) {
		//��ȡ���������ڴ��С
		FileSize = piFileSize.QuadPart;
		return FileSize;
	}
	return 0;
}

//�����ļ���
PCHAR AddFileName(PCHAR pFileName) {
	CHAR FileName[100] = { 0 };
	CHAR* NewFileName = malloc(100);
	if (NewFileName==NULL) {
		return NULL;
	}
	memset(NewFileName, 0, 100);
	CHAR* pAdd = "_Add";

	memcpy(FileName, pFileName, strlen(pFileName) + 1);
	PCHAR pPoint = strrchr(FileName, '.');
	PCHAR pSuffix = pPoint + 1;
	*pPoint = '\0';

	size_t dwLen = strlen(FileName);
	memcpy(NewFileName, FileName, dwLen);
	memcpy(&NewFileName[dwLen], pAdd, strlen(pAdd));
	NewFileName[strlen(NewFileName)] = '.';
	memcpy(&NewFileName[strlen(NewFileName)], pSuffix, strlen(pSuffix));

	return NewFileName;
}

//��80�ֽڿռ����������,��һ�������������
BOOL AddOneSectionNormal(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize) {
	DWORD	dwStartVirtualAddress = 0;
	DWORD	dwStartFileAddress = 0;
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);

	if (!CalcSectionTableAddress(pDosHeader ,&dwStartVirtualAddress, &dwStartFileAddress)) {
		return FALSE;
	}
	//��ʼ��
	IMAGE_SECTION_HEADER	MySectionHeader = { ".tttt",dwSectionSize,
		dwStartVirtualAddress,dwSectionSize,
		dwStartFileAddress,0,0,0,0,
		IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE };
	//����
	memcpy(pZero, &MySectionHeader, sizeof(IMAGE_SECTION_HEADER));
	//ʹ����ӵ��40���ֽڵ�0
	memset((PBYTE)((ULONG_PTR)pZero + sizeof(IMAGE_SECTION_HEADER)), 0, sizeof(IMAGE_SECTION_HEADER));

	//�޸�PEͷ�нڵ�����NumberOfSections
	//�޸�SizeOfImage�Ĵ�С
	SetNumberOfSections(pNtHeader, 1);
	SetSizeOfImage(pNtHeader, dwSectionSize);

	//�޸���������
	// do sth...
	//

	return TRUE;
}

/*
ȥ��dos_stub
��PEͷ��ǰ
�޸�e_lfanew
�����һ����
*/
BOOL	AddSectionAdvanceNtHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize) {
	DWORD	dwStartVirtualAddress = 0;
	DWORD	dwStartFileAddress = 0;
	DWORD	dwSizeOfSectionHeader = GetSizeOfSectionHeader();

	if (!CalcSectionTableAddress(pDosHeader, &dwStartVirtualAddress, &dwStartFileAddress)) {
		return FALSE;
	}
	//��ʼ��
	IMAGE_SECTION_HEADER	MySectionHeader = { ".tttt",dwSectionSize,
		dwStartVirtualAddress,dwSectionSize,
		dwStartFileAddress,0,0,0,0,
		IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE };
	
	//����ͷ��
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	DWORD	dwSizeOfMove = GetSizeOfNtHeaders() + GetSizeOfSectionTable(pDosHeader);
	DWORD	dwSizeOfDos = GetSizeOfDos();
	
	PIMAGE_NT_HEADERS pNewNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + dwSizeOfDos);
	memcpy((PVOID)(pNewNtHeader), pNtHeader, dwSizeOfMove);
	PBYTE	pNewSection = (PBYTE)((ULONG_PTR)pNewNtHeader + dwSizeOfMove);

	//�����µĽڱ�
	memcpy((PVOID)pNewSection, &MySectionHeader, dwSizeOfSectionHeader);

	//�ڱ�ĩβ���40�ֽڵ���
	memset(pNewSection+ dwSizeOfSectionHeader, 0, dwSizeOfSectionHeader);

	//�޸�PEͷ�нڵ�����NumberOfSections
	//�޸�SizeOfImage�Ĵ�С
	//�޸�e_lfanew
	SetNumberOfSections(pNewNtHeader, 1);
	SetSizeOfImage(pNewNtHeader, dwSectionSize);
	SetElfanew(pDosHeader, (LONG)dwSizeOfDos);

	//�޸���������
	// do sth...
	//

	return TRUE;
}

BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	BOOL bResult = FALSE;

	//�ļ�ӳ�䵽
	PBYTE pFile = MyReadFile(pFileName);
	if (pFile != NULL) {
		printf("[+]�ļ���ȡ�ɹ�\n");
		pDosHeader = (PIMAGE_DOS_HEADER)pFile;

		//�ж���û���㹻��0x50�ֽڵ�00�ռ�
		if (JudgeSize(pDosHeader)) {
			printf("[+]���㹻�������ɹ�\n");
			if (!AddOneSectionNormal(pDosHeader, dwSectionSize)) {
				return FALSE;
			}
		}
		else {
			printf("[-]û���㹻�������ռ�\n");
			printf("[+]��PEͷ��ǰ\n");
			if (!AddSectionAdvanceNtHeader(pDosHeader, dwSectionSize)) {
				return FALSE;
			}
		}

		if (MyWriteFile(pDosHeader, dwSectionSize, pCode, pFileName)) {
			printf("[+]�ļ�д��ɹ�\n");
		}
		else {
			return FALSE;
		}
	}

	if (pFile != NULL) {
		VirtualFree(pFile, 0, MEM_RELEASE);
	}



	return TRUE;
}