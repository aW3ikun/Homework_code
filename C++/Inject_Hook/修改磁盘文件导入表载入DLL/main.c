#include<Windows.h>
#include"../../PE/������һ����/_global.h"
#include"../../PE/������һ����/pe.h"

int main(int argc, char* argv[]) {
	BOOL bResult = FALSE;

	PCHAR	pFileName = "D:\\repos\\Homework_code\\C++\\PE\\������һ����\\x64\\Debug\\64-NOTEPAD.EXE";
	//PCHAR	pFileName = "C:\\Users\\awei_\\Downloads\\EverEdit\\EverEdit.exe";
	//PCHAR	pFileName = "D:\\repos\\Homework_code\\C++\\PE\\������һ����\\x64\\\Release\\Test_exe.exe";
	//PCHAR pFileName = "D:\\repos\\Homework_code\\C++\\PE\\������һ����\\Release\\Test_exe.exe";
	PCHAR pDllName = "Test_DLL.dll";
	PCHAR pFuncName = "MyMessageBox";


	//����ɶ���λ�汾�����ʺϼ��ض���λ
	bResult = ExpandSectionToAddImportTable(pFileName, pDllName, pFuncName);

	if (bResult == FALSE) {
		printf("[-]���DLLʧ��\n");
	}
	else {
		printf("[+]���DLL�ɹ�\n");
	}

	system("pause");
	return 0;
	return 0;
}