#include"_global.h"
#include"pe.h"

//读取文件并顺便扩展大小到内存中
PBYTE	MyReadFile(PCHAR pFileName, PDWORD pFileSize, DWORD dwSectionSize) {
	HANDLE hFile = CreateFileA(pFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	int error = GetLastError();
	DWORD	SizeOfFile = 0;
	PBYTE	lpFile = NULL;
	PBYTE	lpFileEnd = NULL;
	DWORD dwBytesToRead = 0;
	DWORD dwBytesRead = 0;
	if (hFile != INVALID_HANDLE_VALUE) {
		//获取文件大小
		if (SizeOfFile = GetFileSize(hFile,NULL)) {
			SizeOfFile = SizeOfFile + dwSectionSize;
			//返回文件大小
			*pFileSize = SizeOfFile;
			//获取最终虚拟内存大小
			dwBytesToRead = SizeOfFile;
			lpFile = VirtualAlloc(NULL, SizeOfFile, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			if (lpFile != NULL) {
				lpFileEnd = lpFile;
				ZeroMemory(lpFile, SizeOfFile);
				//循环读文件，确保读出完整的文件
				do {
					if (!ReadFile(hFile, lpFileEnd, dwBytesToRead, &dwBytesRead, NULL)) {
						int error = GetLastError();
						printf("[-]文件读取失败: %d\n", error);
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
			printf("[-]文件大小获取失败\n");
		}
		CloseHandle(hFile);
	}
	else {
		printf("[-]文件打开失败\n");
	}

	return lpFile;
}

//文件写入,添加剩余数据
BOOL	MyWriteFile(PBYTE pFileBuffer, DWORD FileSize, PCHAR pFileName) {
	DWORD dwBytesToWrite = FileSize;
	DWORD dwBytesWrite = 0;
	BOOL bResult = FALSE;
	//处理文件名
	PCHAR NewFileName = AddFileName(pFileName);
	HANDLE hFile = CreateFileA(NewFileName, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (WriteFile(hFile, pFileBuffer, dwBytesToWrite, &dwBytesWrite, NULL)) {
		bResult = TRUE;
	}

	if (NewFileName != NULL) {
		free(NewFileName);
	}

	if (bResult == FALSE) {
		printf("[-]文件写入失败\n");
	}
	return bResult;
}

//拷贝数据
VOID	MyCopyBuffer(PBYTE	pFileBuffer, DWORD	dwSectionSize, DWORD dwFileSize, PBYTE pCode) {
	PBYTE pBufferStart = (PBYTE)((ULONG_PTR)pFileBuffer - dwSectionSize + dwFileSize);
	memcpy(pBufferStart, pCode, dwSectionSize);
}

/*
1. 判读那是否有足够空间，可以添加一个节表
SizeOfHeaders-(DOS+DOS STUB+NT头+已存在节表) >=2个节表大小
满足才可添加,如果不够需要将NT_HEADER前移
2. 完善新增节表内容
3. 在新添节表后面填充一个（节表）大小的00
4. 修改PE头中节的数量NumberOfSections
5. 修改SizeOfImage的大小
6. 添加新的节的数据内容(内存对齐)
7. 修正新节的属性
Name
VirtualSize
VirtualAddress = 上一个VirtualAddress + SizeOfRawData 符合内存对齐
PointToRawData 等于上一个  PointToRawData + SizeOfRawData 符合文件对齐
SizeOfRawData = VirtualSize
*/

////获取文件大小
//ULONG_PTR MyGetFileSize(HANDLE hFile) {
//	LARGE_INTEGER  piFileSize = { 0 };
//	LONGLONG FileSize = 0;
//	if (GetFileSizeEx(hFile, &piFileSize)) {
//		//获取最终虚拟内存大小
//		FileSize = piFileSize.QuadPart;
//		return FileSize;
//	}
//	return 0;
//}

//处理文件名
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

//有80字节空间就正常扩充,另一个函数添加数据
BOOL AddOneSectionNormal(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize) {
	DWORD	dwStartVirtualAddress = 0;
	DWORD	dwStartFileAddress = 0;
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);

	if (!CalcSectionTableAddress(pDosHeader, &dwStartVirtualAddress, &dwStartFileAddress)) {
		return FALSE;
	}
	//初始化
	IMAGE_SECTION_HEADER	MySectionHeader = { ".tttt",dwSectionSize,
		dwStartVirtualAddress,dwSectionSize,
		dwStartFileAddress,0,0,0,0,
		IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE };
	//拷贝
	memcpy(pZero, &MySectionHeader, sizeof(IMAGE_SECTION_HEADER));
	//使后面拥有40个字节的0
	memset((PBYTE)((ULONG_PTR)pZero + sizeof(IMAGE_SECTION_HEADER)), 0, sizeof(IMAGE_SECTION_HEADER));

	//修改PE头中节的数量NumberOfSections
	//修改SizeOfImage的大小
	AddNumberOfSections(pNtHeader, 1);
	AddSizeOfImage(pNtHeader, dwSectionSize);

	//修改其他东西
	// do sth...
	//

	return TRUE;
}

/*
去掉dos_stub
将PE头提前
修改e_lfanew
再添加一个段
*/
BOOL	AddSectionAdvanceNtHeader(PIMAGE_DOS_HEADER pDosHeader, DWORD dwSectionSize) {
	DWORD	dwStartVirtualAddress = 0;
	DWORD	dwStartFileAddress = 0;
	DWORD	dwSizeOfSectionHeader = GetSizeOfSectionHeader();

	if (!CalcSectionTableAddress(pDosHeader, &dwStartVirtualAddress, &dwStartFileAddress)) {
		return FALSE;
	}
	//初始化
	IMAGE_SECTION_HEADER	MySectionHeader = { ".tttt",dwSectionSize,
		dwStartVirtualAddress,dwSectionSize,
		dwStartFileAddress,0,0,0,0,
		IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE };

	//拷贝头部
	PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDosHeader);
	DWORD	dwSizeOfMove = GetSizeOfNtHeaders() + GetSizeOfSectionTable(pDosHeader);
	DWORD	dwSizeOfDos = GetSizeOfDos();

	PIMAGE_NT_HEADERS pNewNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + dwSizeOfDos);
	memcpy((PVOID)(pNewNtHeader), pNtHeader, dwSizeOfMove);
	PBYTE	pNewSection = (PBYTE)((ULONG_PTR)pNewNtHeader + dwSizeOfMove);

	//拷贝新的节表
	memcpy((PVOID)pNewSection, &MySectionHeader, dwSizeOfSectionHeader);

	//节表末尾添加40字节的零
	memset(pNewSection + dwSizeOfSectionHeader, 0, dwSizeOfSectionHeader);

	//修改PE头中节的数量NumberOfSections
	//修改SizeOfImage的大小
	//修改e_lfanew
	SetElfanew(pDosHeader, (LONG)dwSizeOfDos);
	AddNumberOfSections(pDosHeader, 1);
	AddSizeOfImage(pDosHeader, dwSectionSize);

	//修改其他东西
	// do sth...
	//

	return TRUE;
}

BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	BOOL bResult = FALSE;

	//文件映射到
	DWORD dwFileSize = 0;
	PBYTE pFile = MyReadFile(pFileName, &dwFileSize, dwSectionSize);
	if (pFile != NULL) {
		printf("[+]文件读取成功\n");
		pDosHeader = (PIMAGE_DOS_HEADER)pFile;

		if (!IsPE(pDosHeader)) {
			return FALSE;
		}

		//判断有没有足够的0x50字节的00空间
		if (JudgeSize(pDosHeader)) {
			printf("[+]有足够的区块表成功\n");
			if (!AddOneSectionNormal(pDosHeader, dwSectionSize)) {
				return FALSE;
			}
		}
		else {
			printf("[-]没有足够的区块表空间\n");
			printf("[+]将PE头提前\n");
			if (!AddSectionAdvanceNtHeader(pDosHeader, dwSectionSize)) {
				return FALSE;
			}
		}

		MyCopyBuffer(pFile, dwSectionSize, dwFileSize, pCode);

		//do sth....

		if (MyWriteFile(pDosHeader, dwFileSize, pFileName)) {
			printf("[+]文件写入成功\n");
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
扩大最后一个节
1 . 修改 最后一个节的 SizeOfRawData和VirtualSize改成N
N = (SizeOfRawData >= VirtualSize ? SizeOfRawData : VirtualSize) + Ex
SizeOfRawData = VirtualSize = N
2. SizeOfImage = SizeOfImage + Ex
*/

//扩大一个节 最后一个节
BOOL	ExpandSection(DWORD dwSectionSize, PBYTE pCode, PCHAR pFileName) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	BOOL bResult = FALSE;
	DWORD dwFileSize = 0;
	//文件映射到
	PBYTE pFile = MyReadFile(pFileName, &dwFileSize, dwSectionSize);

	do {
		if (pFile != NULL) {
			printf("[+]文件读取成功\n");
			pDosHeader = (PIMAGE_DOS_HEADER)pFile;

			if (!IsPE(pDosHeader)) {
				bResult = FALSE;
				break;

			}

			//获取最后一个节表，修改属性
			DWORD dwNumberOfSection = GetNumberOfSection(pDosHeader);
			PIMAGE_SECTION_HEADER pLastSectionHeader = GetXXSectionHeader(pDosHeader, dwNumberOfSection);
			//添加节表属性
			AddSectionAttribute(pLastSectionHeader, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
			//符合扩大一个节的习惯，修改最后一个节表的SizeOfRawData 和 VirtualSize
			SetLastSectionRawDataAndVirtualSize(pLastSectionHeader, dwSectionSize);
			if (!AddSizeOfImage(pDosHeader, dwSectionSize)) {
				bResult =  FALSE;
				break;

			}

			MyCopyBuffer(pFile, dwSectionSize, dwFileSize, pCode);

			if (MyWriteFile(pDosHeader, dwFileSize, pFileName)) {
				printf("[+]文件写入成功\n");
				bResult = TRUE;
			}
			else {
				bResult =  FALSE;
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


//合并成一个节
BOOL	MergeOneSection(PCHAR pFileName,DWORD dwSectionSize) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	BOOL bResult = FALSE;
	DWORD dwFileSize = 0;
	//文件映射到
	PBYTE pFile = MyReadFile(pFileName, &dwFileSize, dwSectionSize);

	PBYTE pMemory = NULL;
	do {
		if (pFile != NULL) {
			printf("[+]文件读取成功\n");
			pDosHeader = (PIMAGE_DOS_HEADER)pFile;

			if (!IsPE(pDosHeader)) {
				bResult = FALSE;
				break;
			}

			pMemory = StretchFileToMemory(pDosHeader,&dwFileSize);
			if (pMemory == NULL) {
				DEBUG_INFO("[-]文件拉伸到内存失败");
				bResult = FALSE;
				break;
			}

			//计算所有区段大小
			DWORD dwSize = GetAllSizeOfSection(pMemory);
			SetSizeOfRawDataAndVirtualSize(pMemory, 1, dwSize);

			//修改节属性
			//获取节的属性
			INT Characteristics = 0;
			for (int i = 1; i <= GetNumberOfSection(pMemory); i++) {
				Characteristics |= GetSectionCharacteristics(pMemory, i);
			}
			SetSectionCharacteristics(pMemory, 1, Characteristics);

			//修改NumberOfSections
			SetNumberOfSections(pMemory, 1);

			if (MyWriteFile(pMemory, dwFileSize, pFileName)) {
				printf("[+]文件写入成功\n");
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