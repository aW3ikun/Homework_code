#include<Windows.h>
#include<stdio.h>


//���ļ����ڴ���
PBYTE	MyReadFile(PCHAR pFileName, DWORD dwSectionSize);

//�����ļ���С
DWORD dwFileSize = 0;

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


//���ļ����ڴ���
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
		//ѭ�����ļ���ȷ�������������ļ�
		do {                                                
			if (!ReadFile(hFile, lpFileEnd, dwBytesToRead, &dwBytesRead, NULL)) {
				int error = GetLastError();
				printf("[-]�ļ���ȡʧ��: %d\n",error);
				return NULL;
			}
				
			if (dwBytesRead == 0)
				break;
			dwBytesToRead -= dwBytesRead;
			lpFileEnd += dwBytesRead;
		} while (dwBytesToRead > 0);
	}
	else {
		printf("[-]�ļ���ʧ��\n");
	}
	CloseHandle(hFile);
	return lpFile;
}


BOOL	AddSection(PCHAR pSectionName, DWORD dwSectionSize, BYTE bPadding, PCHAR	pFileName) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PBYTE pFile = MyReadFile(pFileName, dwSectionSize);
	if(pFile!=NULL){
		printf("[+]�ļ���ȡ�ɹ�\n");
		pDosHeader = (PIMAGE_DOS_HEADER)pFile;

	}
	VirtualFree(pFile, 0, MEM_RELEASE);


	return TRUE;
}

/*
ȥ��dos_stub
��PEͷ��ǰ
�޸�e_lfanew
�����һ����
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
		printf("[-]�������ʧ��\n");
	}
	else {
		printf("[-]������γɹ�\n");
	}

	system("pause");
	return 0;
}