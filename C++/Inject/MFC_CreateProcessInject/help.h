#include"pch.h"
#include<ImageHlp.h>
#pragma comment(lib,"Imagehlp.lib")
#pragma pack(push)
#pragma pack(1)
typedef struct {
	//����LoadLibrary
	BYTE pushad;
	BYTE bPush1;
	DWORD dwDllPath;
	BYTE bMovEax;
	DWORD dwLoadLibrary;
	WORD callEax;

	//�޸�ͷ��
	BYTE bMovEsi;
	DWORD dwEsiValue;
	BYTE bMovEdi;
	DWORD dwEdiValue;
	BYTE bMovEcx;
	DWORD dwEcxValue;
	WORD wRepMovsb;
	BYTE popad;
	//��ת��ȥ
	BYTE bPush2;
	DWORD dwEip;
	BYTE bRet;
	BYTE bHeadCode[5];
}ShellCode;

typedef struct {
	BYTE bPush;
	DWORD dwAddr;
	BYTE bRet;
} PUSHRET;

typedef struct {
	BYTE bJmp;
	DWORD dwAddr;
} JMP;
#pragma pack(pop)

DWORD GetEntryPoint(CString pszfilePath);
BOOL Inject(CString pszfileName, CString pszdllPath, CString &pszLog);
DWORD CreateShellCode(PROCESS_INFORMATION pi, LPVOID lpDllPath, BYTE bHeadCode[], DWORD dwBaseAddr);