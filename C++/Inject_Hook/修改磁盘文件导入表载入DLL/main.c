#include<Windows.h>
#include"../../PE/新增加一个节/_global.h"
#include"../../PE/新增加一个节/pe.h"

int main(int argc, char* argv[]) {
	BOOL bResult = FALSE;

	PCHAR	pFileName = "D:\\repos\\Homework_code\\C++\\PE\\新增加一个节\\x64\\Debug\\64-NOTEPAD.EXE";
	//PCHAR	pFileName = "C:\\Users\\awei_\\Downloads\\EverEdit\\EverEdit.exe";
	//PCHAR	pFileName = "D:\\repos\\Homework_code\\C++\\PE\\新增加一个节\\x64\\\Release\\Test_exe.exe";
	//PCHAR pFileName = "D:\\repos\\Homework_code\\C++\\PE\\新增加一个节\\Release\\Test_exe.exe";
	PCHAR pDllName = "Test_DLL.dll";
	PCHAR pFuncName = "MyMessageBox";


	//编译成多少位版本，就适合加载多少位
	bResult = ExpandSectionToAddImportTable(pFileName, pDllName, pFuncName);

	if (bResult == FALSE) {
		printf("[-]添加DLL失败\n");
	}
	else {
		printf("[+]添加DLL成功\n");
	}

	system("pause");
	return 0;
	return 0;
}