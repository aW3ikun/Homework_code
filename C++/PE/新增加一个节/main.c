#include<Windows.h>
#include<stdio.h>


//���ļ����ڴ���
PBYTE	MyReadFile(PCHAR pFileName, DWORD dwSectionSize);

//�����ļ���С
LONGLONG LongFileSize = 0;
PBYTE pZero = NULL;

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


//��ȡ�ļ���˳����չ��С���ڴ���
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
			//��ȡ���������ڴ��С
			LongFileSize = piFileSize.QuadPart;
			dwBytesToRead = LongFileSize;
			lpFile = VirtualAlloc(NULL, LongFileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
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
		else {
			printf("[-]�ļ���С��ȡʧ��\n");
		}

	}
	else {
		printf("[-]�ļ���ʧ��\n");
	}
	CloseHandle(hFile);
	return lpFile;
}

//�ļ�д��
BOOL	MyWriteFile() {

}

//�ж��Ƿ����ռ�
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
		//У���Ƿ�Ϊ0
		//ָ���հ״�
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

	//�ļ�ӳ�䵽
	PBYTE pFile = MyReadFile(pFileName);
	if(pFile!=NULL){
		printf("[+]�ļ���ȡ�ɹ�\n");
		pDosHeader = (PIMAGE_DOS_HEADER)pFile;

		DWORD	dwSizeOfDos = pDosHeader->e_lfanew;
		PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + dwSizeOfDos);

		//�ж���û���㹻��0x50�ֽڵ�00�ռ�
		if (Judge(pDosHeader)){
			printf("[+]���㹻�������ɹ�\n");
			AddOneSectionNormal(pNtHeader);
		}
		

	}
	VirtualFree(pFile, 0, MEM_RELEASE);


	return TRUE;
}

//��80�ֽڿռ����������
BOOL AddOneSectionNormal() {
	//��ȡ���һ���εĲ���
	PIMAGE_SECTION_HEADER pLastSectionHeader = pZero - sizeof(IMAGE_SECTION_HEADER);
	return TRUE;
}

/*
ȥ��dos_stub
��PEͷ��ǰ
�޸�e_lfanew
�����һ����
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
		printf("[-]�������ʧ��\n");
	}
	else {
		printf("[+]������γɹ�\n");
	}

	system("pause");
	return 0;
}