#include"..//������һ����//pe.h"
#include"..//������һ����//_global.h"

//�����ļ���С
LONGLONG LongFileSize = 0;

int main() {
	
	BOOL bResult = FALSE;

	DWORD dwSectionSize = 0x1000;
	PBYTE pCode = NULL;
	PCHAR	pFileName = ".\\64-NOTEPAD.EXE";
	//PCHAR	pFileName = ".\\Test_exe.exe";
	



	pCode = (PBYTE)malloc(dwSectionSize);
	if (pCode == NULL) {
		return NULL;
	}
	memset(pCode, 'B', dwSectionSize);
	//����ɶ���λ�汾�����ʺϼ��ض���λ
	bResult = ExpandSection(dwSectionSize, pCode, pFileName);
	if (pCode != NULL) {
		free(pCode);
	}

	if (bResult == FALSE) {
		printf("[-]�������ʧ��\n");
	}
	else {
		printf("[+]������γɹ�\n");
	}

	system("pause");

	return 0;
}