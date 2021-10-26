#include"..//新增加一个节//pe.h"
#include"..//新增加一个节//_global.h"

int main() {
	BOOL bResult = FALSE;


	//PCHAR	pFileName = ".\\64-NOTEPAD.EXE";
	//PCHAR	pFileName = "C:\\Users\\awei_\\Downloads\\EverEdit\\EverEdit.exe";
	//PCHAR	pFileName = "D:\\repos\\Homework_code\\C++\\PE\\新增加一个节\\x64\\\Release\\Test_exe.exe";
	PCHAR pFileName = "D:\\repos\\Homework_code\\C++\\PE\\新增加一个节\\Release\\Test_exe.exe";


	//编译成多少位版本，就适合加载多少位
	bResult = MergeOneSection(pFileName);

	if (bResult == FALSE) {
		printf("[-]合并区段失败\n");
	}
	else {
		printf("[+]合并区段成功\n");
	}

	system("pause");
	return 0;
	return 0;
}