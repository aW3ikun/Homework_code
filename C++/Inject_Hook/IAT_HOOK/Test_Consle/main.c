#include<Windows.h>
#include<string.h>
ULONG_PTR GetImportDirectory(CONST PCHAR pDllName, CONST PCHAR pFuncName);
typedef int(WINAPI* pfMessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);

pfMessageBoxW OldMessageBoxW = NULL;

int WINAPI MyMessageBoxW(HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType) {
	return OldMessageBoxW(hWnd, L"hello Awei", lpCaption, uType);
}



int main() {

	MessageBoxW(NULL, L"HOOKǰ", L"HOOKǰ", MB_OK);
	//system("pause");
	//ULONG_PTR  a = GetImportDirectory("user32.dll","MessageBoxW");
	//DWORD oldProtected;
	//VirtualProtect(a, 0x8, PAGE_EXECUTE_READWRITE, &oldProtected);
	//OldMessageBoxW = *(PULONG_PTR)a;
	//*(PULONG_PTR)a = MyMessageBoxW;
	//VirtualProtect(a, 0x8, oldProtected, &oldProtected);
	//LoadLibrary(L"IAT_HOOK.dll");
	MessageBoxW(NULL, L"HOOK��", L"HOOK��", MB_OK);
	system("pause");


	//VirtualProtect(a, 0x8, PAGE_EXECUTE_READWRITE, &oldProtected);
	//*(PULONG_PTR)a = OldMessageBoxW;
	//VirtualProtect(a, 0x8, oldProtected, &oldProtected);

	//FreeLibrary(L"IAT_HOOK.dll");

	MessageBoxW(NULL, L"ж��HOOK��", L"ж��HOOK��", MB_OK);
	return 0;
}

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

	//����IAT
	for (int i = 1; i < ImportCount; i++) {
		//����DLL����
		PCHAR pImportDllName = (PCHAR)((ULONG_PTR)hMoudule + pImportDescriptor->Name);
		if (!_stricmp(pImportDllName, pDllName)) {
			PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)((ULONG_PTR)hMoudule + pImportDescriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((ULONG_PTR)hMoudule + pImportDescriptor->FirstThunk);
			PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)(hMoudule)+pINT->u1.AddressOfData);
			int Num = 0;
			//���Һ�����
			while (pINT->u1.AddressOfData != 0) {
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)(hMoudule)+pINT->u1.AddressOfData);
				//ͨ����ŷ���IAT�洢������ַ�ĵ�ַ
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

