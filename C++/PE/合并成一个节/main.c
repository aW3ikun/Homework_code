#include"..//������һ����//pe.h"
#include"..//������һ����//_global.h"

int main() {
	BOOL bResult = FALSE;


	PCHAR	pFileName = ".\\64-NOTEPAD.EXE";
	//PCHAR	pFileName = ".\\Test_exe.exe";


	//����ɶ���λ�汾�����ʺϼ��ض���λ
	bResult = MergeOneSection(pFileName);

	if (bResult == FALSE) {
		printf("[-]�ϲ�����ʧ��\n");
	}
	else {
		printf("[+]�ϲ����γɹ�\n");
	}

	system("pause");
	return 0;
	return 0;
}