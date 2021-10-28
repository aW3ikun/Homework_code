#include"_global.h"
#include"pe.h"

//���PE�Ͱ汾
BOOL checkPeAndBit(PIMAGE_DOS_HEADER pDosHeader){
	return (IsPE(pDosHeader) && IsCurrentBit(pDosHeader));
}

//��ȡ�ļ���˳����չ��С���ڴ���
PBYTE	MyReadFile(PCHAR pFileName, PDWORD pFileSize, DWORD dwSectionSize) {
	HANDLE hFile = CreateFileA(pFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	int error = GetLastError();
	DWORD	SizeOfFile = 0;
	PBYTE	lpFile = NULL;
	PBYTE	lpFileEnd = NULL;
	DWORD dwBytesToRead = 0;
	DWORD dwBytesRead = 0;
	if (hFile != INVALID_HANDLE_VALUE) {
		//��ȡ�ļ���С
		if (SizeOfFile = GetFileSize(hFile, NULL)) {
			SizeOfFile = SizeOfFile + dwSectionSize;
			//�����ļ���С
			*pFileSize = SizeOfFile;
			//��ȡ���������ڴ��С
			dwBytesToRead = SizeOfFile;
			lpFile = VirtualAlloc(NULL, SizeOfFile, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			if (lpFile != NULL) {
				lpFileEnd = lpFile;
				ZeroMemory(lpFile, SizeOfFile);
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
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD FileSize, PCHAR pFileName) {
	DWORD dwBytesToWrite = FileSize;
	DWORD dwBytesWrite = 0;
	BOOL bResult = FALSE;
	//�����ļ���
	PCHAR NewFileName = AddFileName(pFileName);
	HANDLE hFile = CreateFileA(NewFileName, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (WriteFile(hFile, pFileBuffer, dwBytesToWrite, &dwBytesWrite, NULL)) {
		bResult = TRUE;
	}

	if (NewFileName != NULL) {
		free(NewFileName);
	}

	if (bResult == FALSE) {
		printf("[-]�ļ�д��ʧ��\n");
	}
	return bResult;
}

//�������ݵ�ĩβ
VOID	MyCopyBufferToFileEnd(PBYTE	pFileBuffer, DWORD	dwSectionSize, DWORD dwFileSize, PBYTE pCode) {
	PBYTE pBufferStart = (PBYTE)((ULONG_PTR)pFileBuffer - dwSectionSize + dwFileSize);
	memcpy(pBufferStart, pCode, dwSectionSize);
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

////��ȡ�ļ���С
//ULONG_PTR MyGetFileSize(HANDLE hFile) {
//	LARGE_INTEGER  piFileSize = { 0 };
//	LONGLONG FileSize = 0;
//	if (GetFileSizeEx(hFile, &piFileSize)) {
//		//��ȡ���������ڴ��С
//		FileSize = piFileSize.QuadPart;
//		return FileSize;
//	}
//	return 0;
//}

//�����ļ���
PCHAR AddFileName(PCHAR pFileName) {
	CHAR FileName[100] = { 0 };
	CHAR* NewFileName = malloc(100);
	if (NewFileName == NULL) {
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

	if (!CalcSectionTableAddress(pDosHeader, &dwStartVirtualAddress, &dwStartFileAddress)) {
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
	AddNumberOfSections(pNtHeader, 1);
	AddSizeOfImage(pNtHeader, dwSectionSize);

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
	memset(pNewSection + dwSizeOfSectionHeader, 0, dwSizeOfSectionHeader);

	//�޸�PEͷ�нڵ�����NumberOfSections
	//�޸�SizeOfImage�Ĵ�С
	//�޸�e_lfanew
	SetElfanew(pDosHeader, (LONG)dwSizeOfDos);
	AddNumberOfSections(pDosHeader, 1);
	AddSizeOfImage(pDosHeader, dwSectionSize);

	//�޸���������
	// do sth...
	//

	return TRUE;
}

BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	BOOL bResult = FALSE;

	//�ļ�ӳ�䵽
	DWORD dwFileSize = 0;
	PBYTE pFile = MyReadFile(pFileName, &dwFileSize, dwSectionSize);
	if (pFile != NULL) {
		printf("[+]�ļ���ȡ�ɹ�\n");
		pDosHeader = (PIMAGE_DOS_HEADER)pFile;

		if (!checkPeAndBit(pDosHeader)) {
			return FALSE;
		}

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

		MyCopyBufferToFileEnd(pFile, dwSectionSize, dwFileSize, pCode);

		//do sth....

		if (MyWriteFile(pDosHeader, dwFileSize, pFileName)) {
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

/*
�������һ����
1 . �޸� ���һ���ڵ� SizeOfRawData��VirtualSize�ĳ�N
N = (SizeOfRawData >= VirtualSize ? SizeOfRawData : VirtualSize) + Ex
SizeOfRawData = VirtualSize = N
2. SizeOfImage = SizeOfImage + Ex
*/

//����һ���� ���һ����
BOOL	ExpandSection(DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	BOOL bResult = FALSE;
	DWORD dwFileSize = 0;
	//�ļ�ӳ�䵽
	PBYTE pFile = MyReadFile(pFileName, &dwFileSize, dwSectionSize);

	do {
		if (pFile != NULL) {
			printf("[+]�ļ���ȡ�ɹ�\n");
			pDosHeader = (PIMAGE_DOS_HEADER)pFile;

			if (!checkPeAndBit(pDosHeader)) {
				bResult = FALSE;
				break;

			}

			//��ȡ���һ���ڱ��޸�����
			DWORD dwNumberOfSection = GetNumberOfSection(pDosHeader);
			PIMAGE_SECTION_HEADER pLastSectionHeader = GetXXSectionHeader(pDosHeader, dwNumberOfSection);
			//��ӽڱ�����
			AddSectionAttribute(pLastSectionHeader, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
			//��������һ���ڵ�ϰ�ߣ��޸����һ���ڱ��SizeOfRawData �� VirtualSize
			SetLastSectionRawDataAndVirtualSize(pLastSectionHeader, dwSectionSize);
			if (!AddSizeOfImage(pDosHeader, dwSectionSize)) {
				bResult = FALSE;
				break;

			}

			MyCopyBufferToFileEnd(pFile, dwSectionSize, dwFileSize, pCode);

			if (MyWriteFile(pDosHeader, dwFileSize, pFileName)) {
				printf("[+]�ļ�д��ɹ�\n");
				bResult = TRUE;
			}
			else {
				bResult = FALSE;
				break;
			}
		}
		else {
			return FALSE;
		}
	} while (0);

	if (pFile != NULL) {
		VirtualFree(pFile, 0, MEM_RELEASE);
	}

	return bResult;
}

//����һ���ڣ�����Ӷ���ĵ����
BOOL	ExpandSectionToAddImportTable(PCHAR pFileName, PCHAR pDllName, PCHAR pFuncName) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	BOOL bResult = FALSE;
	DWORD dwFileSize = 0;
	//Ĭ������0x200�ֽ�
	DWORD	dwExpandSize = 0x200;
	//�ļ�ӳ�䵽
	PBYTE pFile = MyReadFile(pFileName, &dwFileSize, dwExpandSize);

	do {
		if (pFile != NULL) {
			printf("[+]�ļ���ȡ�ɹ�\n");
			pDosHeader = (PIMAGE_DOS_HEADER)pFile;

			if (!checkPeAndBit(pDosHeader)) {
				bResult = FALSE;
				break;

			}

			//��ȡ���һ���ڱ��޸�����
			DWORD dwNumberOfSection = GetNumberOfSection(pDosHeader);
			PIMAGE_SECTION_HEADER pLastSectionHeader = GetXXSectionHeader(pDosHeader, dwNumberOfSection);
			//��ӽڱ�����
			AddSectionAttribute(pLastSectionHeader, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
			//��������һ���ڵ�ϰ�ߣ��޸����һ���ڱ��SizeOfRawData �� VirtualSize
			SetLastSectionRawDataAndVirtualSize(pLastSectionHeader, dwExpandSize);
			if (!AddSizeOfImage(pDosHeader, dwExpandSize)) {
				bResult = FALSE;
				break;

			}

			//���е������
			pZero = (PBYTE)((ULONG_PTR)pFile - dwExpandSize);
			DWORD	dwImportTableRva = GetDataDirectoryRVA(pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);
			DWORD	dwImportTableSize = GetDataDirectorySize(pDosHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);

			PBYTE pImportTable = (PBYTE)RVAToOffset(pDosHeader, dwImportTableRva);
			if (!memcpy_s(pZero, dwExpandSize, pImportTable, dwImportTableSize)) {
				DEBUG_INFO("[-]���������ʧ��\n");
				bResult = FALSE;
				break;
			}
			else {
				pZero += dwImportTableSize;
			}
			//׷�ӵ����
			IMAGE_IMPORT_DESCRIPTOR NewImportDescriptor = { 0 };

			//׷��8���ֽڵ�N��8���ֽڵ�IAT��
			
			//׷��һ�� IMAGE_IMPORT_BY_NAME�ṹ, ǰ2���ֽ���0�����Ǻ��������ַ���
			
			//��IMAGE_IMPORT_BY_NAME�ṹ��RA��ֵ��N��AT���еĵ�һ��
			
			//����ռ�洢L�����ַ����������ַ�����RVAŷֵ��ac����
			
			//����IMAGE_DATA_DIRECT0RY�ṹ�� VirtualAddress��Sie
			

			//MyCopyBufferToFileEnd(pFile, dwSectionSize, dwFileSize, pCode);

			if (MyWriteFile(pDosHeader, dwFileSize, pFileName)) {
				printf("[+]�ļ�д��ɹ�\n");
				bResult = TRUE;
			}
			else {
				bResult = FALSE;
				break;
			}
		}
		else {
			return FALSE;
		}
	} while (0);

	if (pFile != NULL) {
		VirtualFree(pFile, 0, MEM_RELEASE);
	}

	return bResult;
}


//�ϲ���һ����
BOOL	MergeOneSection(PCHAR pFileName, DWORD dwSectionSize) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	BOOL bResult = FALSE;
	DWORD dwFileSize = 0;
	//�ļ�ӳ�䵽
	PBYTE pFile = MyReadFile(pFileName, &dwFileSize, dwSectionSize);

	PBYTE pMemory = NULL;
	do {
		if (pFile != NULL) {
			printf("[+]�ļ���ȡ�ɹ�\n");
			pDosHeader = (PIMAGE_DOS_HEADER)pFile;

			if (!checkPeAndBit(pDosHeader)) {
				bResult = FALSE;
				break;
			}

			pMemory = StretchFileToMemory(pDosHeader, &dwFileSize);
			if (pMemory == NULL) {
				DEBUG_INFO("[-]�ļ����쵽�ڴ�ʧ��");
				bResult = FALSE;
				break;
			}

			//�����������δ�С
			DWORD dwSize = GetAllSizeOfSection(pMemory);
			SetSizeOfRawDataAndVirtualSize(pMemory, 1, dwSize);

			//�޸Ľ�����
			//��ȡ�ڵ�����
			INT Characteristics = 0;
			for (int i = 1; i <= GetNumberOfSection(pMemory); i++) {
				Characteristics |= GetSectionCharacteristics(pMemory, i);
			}
			SetSectionCharacteristics(pMemory, 1, Characteristics);

			//�޸�NumberOfSections
			SetNumberOfSections(pMemory, 1);

			if (MyWriteFile(pMemory, dwFileSize, pFileName)) {
				printf("[+]�ļ�д��ɹ�\n");
				bResult = TRUE;
			}
			else {
				bResult = FALSE;
				break;
			}
		}
		else {
			bResult = FALSE;
			break;
		}
	} while (0);

	if (pMemory != NULL) {
		VirtualFree(pMemory, 0, MEM_RELEASE);
	}
	if (pFile != NULL) {
		VirtualFree(pFile, 0, MEM_RELEASE);
	}
	return bResult;
}