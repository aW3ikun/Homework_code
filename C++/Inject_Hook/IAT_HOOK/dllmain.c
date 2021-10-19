// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include<Windows.h>
#include<string.h>

typedef int(WINAPI* pfMessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);

VOID IATHOOK();
VOID UNIATHOOK();
ULONG_PTR GetImportDirectory(CONST PCHAR pDllName, CONST PCHAR pFuncName);
int WINAPI MyMessageBoxW(HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType);

pfMessageBoxW OldMessageBoxW = NULL;
ULONG_PTR  ulFunc = NULL;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH: {
		IATHOOK();
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH: {
		UNIATHOOK();
		break;
	}
	case DLL_PROCESS_DETACH: {
		UNIATHOOK();
		break;
	}

	}
	return TRUE;
}

//获取进程导出表 Import_Directory
ULONG_PTR GetImportDirectory(CONST PCHAR pDllName, CONST PCHAR pFuncName) {
	HMODULE hMoudule = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMoudule;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pNtHeader + sizeof(pNtHeader->Signature) + sizeof(pNtHeader->FileHeader));
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionHeader->DataDirectory;

	LONG ImportRva = pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	LONG ImportSize = pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	LONG ImportCount = ImportSize / sizeof(IMAGE_IMPORT_DESCRIPTOR) - 1;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)hMoudule + ImportRva);

	//查找IAT
	for (int i = 1; i < ImportCount; i++) {
		//查找DLL名字
		PCHAR pImportDllName = (PCHAR)((ULONG_PTR)hMoudule + pImportDescriptor->Name);
		if (!_stricmp(pImportDllName, pDllName)) {
			PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)((ULONG_PTR)hMoudule + pImportDescriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((ULONG_PTR)hMoudule + pImportDescriptor->FirstThunk);
			PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)(hMoudule)+pINT->u1.AddressOfData);
			int Num = 0;
			//查找函数名
			while (pINT->u1.AddressOfData != 0) {
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)(hMoudule)+pINT->u1.AddressOfData);
				//通过序号反推IAT存储函数地址的地址
				if (!_stricmp(pImportByName->Name, pFuncName)) {
					return &pIAT[Num];
				}
				pINT++;
				Num++;
			}
		}
		pImportDescriptor++;
	}
	return NULL;
}


int WINAPI MyMessageBoxW(HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType) {
	return OldMessageBoxW(hWnd, L"hello Awei", lpCaption, uType);
}

VOID IATHOOK() {
	ulFunc = GetImportDirectory("user32.dll", "MessageBoxW");
	DWORD oldProtected;
	VirtualProtect((LPVOID)ulFunc, 0x8, PAGE_EXECUTE_READWRITE, &oldProtected);
	OldMessageBoxW = *(PULONG_PTR)ulFunc;
	*(PULONG_PTR)ulFunc = MyMessageBoxW;
	VirtualProtect(ulFunc, 0x8, oldProtected, &oldProtected);


}
VOID UNIATHOOK() {
	DWORD oldProtected;
	VirtualProtect(ulFunc, 0x8, PAGE_EXECUTE_READWRITE, &oldProtected);
	*(PULONG_PTR)ulFunc = OldMessageBoxW;
	VirtualProtect(ulFunc, 0x8, oldProtected, &oldProtected);
}