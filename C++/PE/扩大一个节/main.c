#include"..//新增加一个节//pe.h"
#include"..//新增加一个节//_global.h"

//最终文件大小
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
	//编译成多少位版本，就适合加载多少位
	bResult = ExpandSection(dwSectionSize, pCode, pFileName);
	if (pCode != NULL) {
		free(pCode);
	}

	if (bResult == FALSE) {
		printf("[-]添加区段失败\n");
	}
	else {
		printf("[+]添加区段成功\n");
	}

	system("pause");

	return 0;
}