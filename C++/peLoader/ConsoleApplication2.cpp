// ConsoleApplication2.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>

using namespace std;
extern "C" void _fastcall jmp_func(DWORD_PTR a1);


static PIMAGE_NT_HEADERS GetNtHeader(IN LPVOID lpBaseAddress) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBaseAddress + pDos->e_lfanew);
	return pNt;
}
FARPROC MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	PIMAGE_NT_HEADERS pNt = GetNtHeader(hModule);
	DWORD_PTR dwExportTableRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD_PTR dwSizeOfExport = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	PIMAGE_EXPORT_DIRECTORY lpExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + dwExportTableRVA);
	PDWORD pEAT = (PDWORD)((DWORD_PTR)hModule + lpExportTable->AddressOfFunctions);
	PDWORD pENT = (PDWORD)((DWORD_PTR)hModule + lpExportTable->AddressOfNames);
	PWORD pEOT = (PWORD)((DWORD_PTR)hModule + lpExportTable->AddressOfNameOrdinals);
	DWORD dwBase = lpExportTable->Base;
	DWORD dwNumberOfFunctions = lpExportTable->AddressOfFunctions;
	DWORD dwNumberOfNames = lpExportTable->NumberOfNames;
	FARPROC pRet = NULL;

	DWORD_PTR dwProcName = (DWORD_PTR)lpProcName;
	if ((dwProcName & 0xFFFF0000) == 0)
	{
		//序号
		if (dwProcName < dwBase || dwProcName > dwBase + dwNumberOfFunctions) return 0;
		pRet = (FARPROC)((DWORD_PTR)pEAT[dwProcName - dwBase] + (DWORD_PTR)hModule);
	}
	else {
		//文字
		for (size_t i = 0; i < dwNumberOfNames; i++)
		{
			PCHAR lpStrFunc = (PCHAR)((DWORD_PTR)hModule + (DWORD_PTR)pENT[i]);
			if (strcmp(lpStrFunc, lpProcName) == 0) {
				pRet = (FARPROC)((DWORD_PTR)pEAT[pEOT[i]] + (DWORD_PTR)(hModule));
			}
		}
	}
	if ((DWORD_PTR)pRet < (DWORD_PTR)hModule + dwExportTableRVA || (DWORD_PTR)pRet >((DWORD_PTR)hModule + dwExportTableRVA + dwSizeOfExport)) return pRet;
	//判断是否有'.' 判断是否是dll
	PCHAR lpTempDLL = NULL;
	PCHAR lpFunction = NULL;
	lstrcpyA(lpTempDLL, (PCHAR)pRet);
	PCHAR pChar = strchr(lpTempDLL, '.');
	if (!pChar) return  pRet;
	//拼接dll名字,继续加载dll
	*pChar = 0;
	lstrcpyA(lpFunction, pChar + 1);
	lstrcatA(lpTempDLL, ".dll");
	HMODULE hModule_2 = LoadLibraryA(lpTempDLL);
	if (hModule_2 == INVALID_HANDLE_VALUE) return pRet;
	return MyGetProcAddress(hModule_2, lpFunction);

}
BOOL OutLastError() {
	cout << "Error: " << GetLastError() << endl;
	return FALSE;
}
void ExitProcess_Hook(UINT uExitCode)
{

	MessageBox(NULL, L" 已经 Hook ExitProcess ", L"Hook", MB_OK);
	ExitProcess(uExitCode);
}
LPVOID ReadFile2Memory(LPWSTR file_path, OUT DWORD_PTR dwSize, HANDLE hFile) {
	//读取PE文件到内存中
	hFile = CreateFile(file_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {                            //  文件打开失败，返回错误值
		cout << "[-] CreateFile " << endl;
		OutLastError();
		return NULL;
	}
	dwSize = GetFileSize(hFile, NULL);
	LPVOID lpFileAddress = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	BOOL bValue = ReadFile(hFile, lpFileAddress, dwSize, (LPDWORD)&dwSize, NULL);

	if (FALSE == bValue) {
		cout << "[-] ReadFile" << endl;
		OutLastError();
		return NULL;
	}
	return lpFileAddress;
}
BOOL IsPeFile(LPVOID lpBaseAddress) {
	//判断是否为PE文件
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((UINT_PTR)lpBaseAddress + pDos->e_lfanew);
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE || pNt->Signature != IMAGE_NT_SIGNATURE) {
		cout << "[-] Not PE" << endl;
		return FALSE;
	}
	else
	{
		cout << "[+] PE";
		return TRUE;
	}
}
LPVOID AllocMemory(PIMAGE_NT_HEADERS pNt,LPVOID lpFileAddress) {
	//申请内存
	DWORD_PTR dwImageBase = pNt->OptionalHeader.ImageBase;
	DWORD_PTR dwSizeOfImage = pNt->OptionalHeader.SizeOfImage;
	DWORD_PTR dwCharacteristics = pNt->FileHeader.Characteristics;
	LPVOID lpBaseAddress = VirtualAlloc((LPVOID)dwImageBase, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (GetLastError() == 0) {
		cout << "[+] 程序基地址为 0x" << hex << lpBaseAddress << endl;
		return lpBaseAddress;
	}
	else if (GetLastError() && ((dwCharacteristics | IMAGE_FILE_RELOCS_STRIPPED) - dwCharacteristics != 0))
	{
		lpBaseAddress = VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		cout << "[+] 重定位基址为 0x" << hex << (DWORD_PTR)lpBaseAddress << endl;
		return lpBaseAddress;
	}
	else {
		cout << "[-] 重定位基址失败" << endl;
		VirtualFree(lpFileAddress, 0, MEM_RELEASE);
		return NULL;
	}
}
VOID CopyNtHeader(_Out_writes_bytes_all_(_Size) void* _Dst,_In_reads_bytes_(_Size) void const* _Src,_In_	size_t      _Size) {
	//拷贝NT头及之前的头
	RtlCopyMemory(_Dst, _Src, _Size);
}
VOID CopySection(LPVOID lpFileAddress,LPVOID lpBaseAddress , PIMAGE_NT_HEADERS pNt) {
	//拷贝区块
	DWORD_PTR dwNumberOfSection = pNt->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER	lpImageSectionTable = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pNt + sizeof(IMAGE_NT_HEADERS));
	for (size_t i = 0; i < dwNumberOfSection; i++)
	{
		DWORD_PTR dwVirtualAddress = lpImageSectionTable->VirtualAddress;
		DWORD_PTR dwSizeOfRawData = lpImageSectionTable->SizeOfRawData;
		DWORD_PTR dwPointerToRawData = lpImageSectionTable->PointerToRawData;

		LPVOID lpRawOfData = (LPVOID)((DWORD_PTR)lpFileAddress + dwPointerToRawData);
		LPVOID lpMemory = (LPVOID)((DWORD_PTR)lpBaseAddress + dwVirtualAddress);

		RtlCopyMemory(lpMemory, lpRawOfData, dwSizeOfRawData);
		cout << "[+] 正在拷贝 " << lpImageSectionTable->Name << " 到 0x" << hex << lpMemory << endl;
		lpImageSectionTable = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageSectionTable + sizeof(IMAGE_SECTION_HEADER));
	}
	if (lpFileAddress != 0) {
		if (VirtualFree(lpFileAddress, 0, MEM_RELEASE)) {
			pNt = NULL;
			cout << "[+] 释放文件内存成功" << endl;
		}
		else {
			cout << "[-] 释放文件内存失败 " << endl;
		}
	}
}
BOOL BuildIAT(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pMemNt) {
	//修复导入表
	FARPROC procAddr;
	DWORD_PTR dwImportTableRVA = pMemNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (dwImportTableRVA == NULL) {
		cout << "[-] 无导入表" << endl;
	}
	else {
		PIMAGE_IMPORT_DESCRIPTOR lpImportTableaddress = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpBaseAddress + dwImportTableRVA);
		while (lpImportTableaddress->FirstThunk) {
			LPCSTR dwDllName = (LPCSTR)((DWORD_PTR)lpBaseAddress + lpImportTableaddress->Name);
			HMODULE hDll = LoadLibraryA(dwDllName);
			if (hDll == NULL) {
				OutLastError();
				return FALSE;
			}
			cout << "[+] 修正导入库 " << dwDllName << endl;
			PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + lpImportTableaddress->FirstThunk);
			while (pThunkData->u1.AddressOfData != 0)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pThunkData->u1.Ordinal)) {
#if defined(_WIN64)
					DWORD_PTR dwOrdinal = (DWORD_PTR)pThunkData & 0x7FFFFFFFFFFFFFFF;  

#else
					DWORD_PTR dwOrdinal = (DWORD_PTR)(pThunkData->u1.AddressOfData) & 0x7FFFFFFF;
#endif // #if defined(_WIN64)
					procAddr = MyGetProcAddress(hDll, (LPCSTR)(dwOrdinal));
					pThunkData->u1.AddressOfData = (DWORD_PTR)procAddr;
					cout << "[+] 正在修正函数:　" << dwDllName << "序号" << dwOrdinal << " 到 0x" << hex << procAddr << endl;
				}
				else {
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpBaseAddress + pThunkData->u1.AddressOfData);
					//procAddr = GetProcAddress(hDll, (LPCSTR)(pImportByName->Name));
					if (strcmp(pImportByName->Name, "ExitProcess") == 0) {
						procAddr = (FARPROC)&ExitProcess_Hook;
					}
					else {
						procAddr = GetProcAddress(hDll, (LPCSTR)(pImportByName->Name));
					}
					pThunkData->u1.AddressOfData = (DWORD_PTR)procAddr;
					cout << "[+] 正在修正函数:　" << pImportByName->Name << " 到 0x" << hex << procAddr << endl;
				}
				pThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)pThunkData + sizeof(DWORD_PTR));
			}
			lpImportTableaddress = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpImportTableaddress + sizeof(IMAGE_IMPORT_DESCRIPTOR));
			cout << endl;
		}
	}
	return TRUE;
}
VOID FixReloc(LPVOID lpBaseAddress, PIMAGE_NT_HEADERS pMemNt) {
	//根据重定位表修复代码
	DWORD_PTR dwBaseRelocRVA = pMemNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	if (dwBaseRelocRVA == NULL) {
		cout << "[-] 无重定位表" << endl;
	}
	else {
		PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)(dwBaseRelocRVA + (DWORD_PTR)lpBaseAddress);
		DWORD_PTR dwOffet = (DWORD_PTR)lpBaseAddress - pMemNt->OptionalHeader.ImageBase;
		while (pBaseReloc->VirtualAddress != 0) {
			cout << "[+] 重定位页为 0x" << hex << pBaseReloc << endl;
			DWORD_PTR dwBaseReloc = (DWORD_PTR)lpBaseAddress + pBaseReloc->VirtualAddress;
			DWORD_PTR dwNumber = ((pBaseReloc->SizeOfBlock) - 8) >> 1;
			for (size_t i = 0; i < dwNumber; i++)
			{
				PWORD pTypeOffset = (PWORD)((DWORD_PTR)pBaseReloc + 2 * sizeof(DWORD) + i * sizeof(WORD));
				if (((*pTypeOffset & 0xF000) >> 12) == IMAGE_REL_BASED_HIGHLOW) {
					DWORD_PTR wTypeOffset = (*pTypeOffset & 0x0FFF | 0x0000000);
					PDWORD_PTR dwRelocAddress = (PDWORD_PTR)(wTypeOffset + dwBaseReloc);
					//cout << "[+] 0x" << hex << dwRelocAddress << " 正在被重定位" << endl;
					*dwRelocAddress = (*dwRelocAddress + dwOffet);
				}
			}
			pBaseReloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pBaseReloc + pBaseReloc->SizeOfBlock);
		}
	}
}
VOID Jmp(LPVOID lpBaseAddress,PIMAGE_NT_HEADERS pMemNt) {
	//跳转执行
	DWORD_PTR dwEntryPoint = (DWORD_PTR)lpBaseAddress + (DWORD_PTR)pMemNt->OptionalHeader.AddressOfEntryPoint;
#if defined(_WIN64)
	jmp_func(dwEntryPoint);
#else
	__asm {
		jmp dwEntryPoint; =
	}
#endif
	if (lpBaseAddress != 0) {
		if (VirtualFree(lpBaseAddress, 0, MEM_RELEASE)) {
			cout << "[+] 释放进程内存成功" << endl;
		}
		else {
			cout << "[-] 释放进程内存失败 " << endl;
		}
	}
}
BOOL Loader(LPWSTR file_path) {
	DWORD_PTR dwSize = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPVOID lpFileAddress = ReadFile2Memory(file_path, dwSize, hFile);
	if (lpFileAddress == NULL) return FALSE;
	if(!IsPeFile(lpFileAddress)) return FALSE;
	PIMAGE_NT_HEADERS pNt = GetNtHeader(lpFileAddress);
	LPVOID lpBaseAddress = AllocMemory(pNt, lpFileAddress);
	CopyNtHeader(lpBaseAddress, lpFileAddress, pNt->OptionalHeader.SizeOfHeaders);
	CopySection(lpFileAddress, lpBaseAddress, pNt);
	CloseHandle(hFile);

	PIMAGE_NT_HEADERS pMemNt = GetNtHeader(lpBaseAddress);
	if(!BuildIAT(lpBaseAddress, pMemNt))	return FALSE;

	FixReloc(lpBaseAddress, pMemNt);
	Jmp(lpBaseAddress, pMemNt);
	//FARPROC  Test_1 = MyGetProcAddress((HMODULE)lpBaseAddress, "Test_2");
	//Test_1();
	return TRUE;
}

int main()
{
	int nArgs;
	LPWSTR* szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (!Loader(szArglist[1]))
		cout << "[-] failed! " << endl;

	system("pause");
}
