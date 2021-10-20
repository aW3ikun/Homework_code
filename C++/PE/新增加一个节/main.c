#include<Windows.h>
#include<stdio.h>


//读文件到内存中
PBYTE	MyReadFile(PCHAR pFileName, DWORD dwSectionSize);

//最终文件大小
LONGLONG LongFileSize = 0;
PBYTE pZero = NULL;

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


//读取文件并顺便扩展大小到内存中
PBYTE	MyReadFile(PCHAR pFileName) {
	HANDLE hFile = CreateFileA(pFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	//int error = GetLastError();
	PBYTE	lpFile = NULL;
	PBYTE	lpFileEnd = NULL;
	DWORD dwBytesToRead = 0;
	DWORD dwBytesRead = 0;
	if (hFile != INVALID_HANDLE_VALUE) {
		LARGE_INTEGER  piFileSize = { 0 };
		if (GetFileSizeEx(hFile, &piFileSize)) {
			//获取最终虚拟内存大小
			LongFileSize = piFileSize.QuadPart;
			dwBytesToRead = LongFileSize;
			lpFile = VirtualAlloc(NULL, LongFileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
			lpFileEnd = lpFile;
			ZeroMemory(lpFile, LongFileSize);
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
		else {
			printf("[-]文件大小获取失败\n");
		}

	}
	else {
		printf("[-]文件打开失败\n");
	}
	CloseHandle(hFile);
	return lpFile;
}

//文件写入
BOOL	MyWriteFile() {

}

//判断是否空余空间
BOOL	Judge(PIMAGE_DOS_HEADER	pDosHeader) {
	//DOS+DOS_Stub
	DWORD	dwSizeOfDos = pDosHeader->e_lfanew;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + dwSizeOfDos);

	DWORD	dwSizeOfNtHeaders = sizeof(IMAGE_NT_HEADERS);
	DWORD	dwSizeOfSectionTable = sizeof(IMAGE_SECTION_HEADER) * (pNtHeader->FileHeader.NumberOfSections);

	DWORD	dwSizeOfNtAndSection = (dwSizeOfNtHeaders + dwSizeOfSectionTable);
	DWORD	dwDiff = pNtHeader->OptionalHeader.SizeOfHeaders - (dwSizeOfNtHeaders + dwSizeOfSectionTable);

	if (dwDiff >= 0x50)
	{
		//校验是否都为0
		//指到空白处
		pZero = (PBYTE)((ULONG_PTR)pNtHeader + dwSizeOfNtAndSection);
		for (int i = 0; i < 0x50; i++) {
			if (*(pZero + i) != 0x00) {
				break;
			}
		}
		return TRUE;
	}
	return FALSE;
}

BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, BYTE bPadding, PCHAR pFileName) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	BOOL bResult = FALSE;

	//文件映射到
	PBYTE pFile = MyReadFile(pFileName);
	if(pFile!=NULL){
		printf("[+]文件读取成功\n");
		pDosHeader = (PIMAGE_DOS_HEADER)pFile;

		DWORD	dwSizeOfDos = pDosHeader->e_lfanew;
		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + dwSizeOfDos);

		//判断有没有足够的0x50字节的00空间
		if (Judge(pDosHeader)){
			printf("[+]有足够的区块表成功\n");
			AddOneSectionNormal(pNtHeader);
		}
		

	}
	VirtualFree(pFile, 0, MEM_RELEASE);


	return TRUE;
}

//有80字节空间就正常扩充
BOOL AddOneSectionNormal() {
	//获取最后一个段的参数
	PIMAGE_SECTION_HEADER pLastSectionHeader = pZero - sizeof(IMAGE_SECTION_HEADER);
	return TRUE;
}

/*
去掉dos_stub
将PE头提前
修改e_lfanew
再添加一个段
*/
BOOL	AddSectionAdvanceNtHeader(PCHAR pSectionName, DWORD dwSectionSize, BYTE bPadding, PCHAR	pFileName) {


}


int main() {
	BOOL bResult = FALSE;

	PCHAR pSectionName = ".tttt";
	DWORD dwSectionSize = 0x1000;
	BYTE bPadding = 0x01;
	PCHAR	pFileName = ".\\Test_exe.exe";

	bResult = AddSection(pSectionName, dwSectionSize, bPadding, pFileName);

	if (bResult == FALSE) {
		printf("[-]添加区段失败\n");
	}
	else {
		printf("[+]添加区段成功\n");
	}

	system("pause");
	return 0;
}