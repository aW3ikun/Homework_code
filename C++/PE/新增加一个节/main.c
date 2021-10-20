#include<Windows.h>
#include<stdio.h>


//读文件到内存中
PBYTE	MyReadFile(PCHAR pFileName, DWORD dwSectionSize);

//最终文件大小
DWORD dwFileSize = 0;

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


//读文件到内存中
PBYTE	MyReadFile(PCHAR pFileName, DWORD dwSectionSize) {
	HANDLE hFile = CreateFileA(pFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	int error = GetLastError();
	PBYTE	lpFile = NULL;
	PBYTE	lpFileEnd = NULL;
	DWORD dwBytesToRead = 0;
	DWORD dwBytesRead = 0;
	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD dwSize = GetFileSize(hFile, NULL);
		dwFileSize = dwSize + dwSectionSize;
		lpFile = VirtualAlloc(NULL, dwFileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		lpFileEnd = lpFile;
		ZeroMemory(lpFile, dwFileSize);
		//循环读文件，确保读出完整的文件
		do {                                                
			if (!ReadFile(hFile, lpFileEnd, dwBytesToRead, &dwBytesRead, NULL)) {
				int error = GetLastError();
				printf("[-]文件读取失败: %d\n",error);
				return NULL;
			}
				
			if (dwBytesRead == 0)
				break;
			dwBytesToRead -= dwBytesRead;
			lpFileEnd += dwBytesRead;
		} while (dwBytesToRead > 0);
	}
	else {
		printf("[-]文件打开失败\n");
	}
	CloseHandle(hFile);
	return lpFile;
}


BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, BYTE bPadding, PCHAR	pFileName) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PBYTE pFile = MyReadFile(pFileName, dwSectionSize);
	if(pFile!=NULL){
		printf("[+]文件读取成功\n");
		pDosHeader = (PIMAGE_DOS_HEADER)pFile;

	}
	VirtualFree(pFile, 0, MEM_RELEASE);


	return TRUE;
}

/*
去掉dos_stub
将PE头提前
修改e_lfanew
再添加一个段
*/
BOOL	AdvanceAddSection(PCHAR pSectionName, DWORD dwSectionSize, BYTE bPadding, PCHAR	pFileName) {


}

int main() {
	BOOL bResult = FALSE;

	PCHAR pSectionName = ".tttt";
	DWORD dwSectionSize = 0x1000;
	BYTE bPadding = 0x01;
	PCHAR	pFileName = ".\\123.exe";

	bResult = AddSection(pSectionName, dwSectionSize, bPadding, pFileName);

	if (bResult == FALSE) {
		printf("[-]添加区段失败\n");
	}
	else {
		printf("[-]添加区段成功\n");
	}

	system("pause");
	return 0;
}