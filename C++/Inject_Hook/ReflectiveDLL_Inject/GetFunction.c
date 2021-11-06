#include"GetFunction.h"

//右移计算
__forceinline DWORD ror(DWORD d) {
	return _rotr(d, HASH_KEY);
}

//计算函数名hash
__forceinline DWORD hash(char* c) {
	register	DWORD h = 0;
	do {
		h = ror(h);
		h += *c;
	} while (*++c);

	return h;
}

//获取peb地址
inline ULONG_PTR GetPeb() {
#ifdef _WIN64
	return  (ULONG_PTR)__readgsqword(0x60);
#else
	return (ULONG_PTR)__readfsdword(0x30);
#endif // WIN_X64
}

//获取Ldr地址
inline ULONG_PTR GetLdr(ULONG_PTR uiPebAddr) {
	return (ULONG_PTR)(((PPEB)uiPebAddr)->Ldr);
}

//全部转为大写，然后hash计算
inline VOID ComputeHash(ULONG_PTR	uiDllName, ULONG_PTR	uiDllLength, PDWORD	uiDllHash) {
	if (uiDllName == NULL)
		return;
	do {
		*uiDllHash = ror((DWORD)*uiDllHash);

		//大写转换
		if (*(BYTE*)uiDllName >= 'a')
			*uiDllHash += (*(BYTE*)uiDllName) - 0x20;
		else
			*uiDllHash += (*(BYTE*)uiDllName);
		uiDllName++;
	} while (--uiDllLength);
}

//获取特定函数地址
ULONG_PTR GetFunction(DWORD dwDllHash, DWORD dwFuncHash) {
	//返回的地址
	ULONG_PTR	uiResult = 0;

	ULONG_PTR	uiPebAddr = GetPeb();
	ULONG_PTR	uiLdrAddr = GetLdr(uiPebAddr);
	ULONG_PTR	uiLdrFlink = (ULONG_PTR)((PPEB_LDR_DATA)uiLdrAddr)->InMemoryOrderModuleList.Flink;
	//DLL相关信息
	ULONG_PTR	uiDllName;
	ULONG_PTR	uiDllLength;
	ULONG_PTR	uiBaseAddr;
	DWORD		dwLdrDllHash;
	DWORD		dwLdrFuncHash;
	//导出表
	ULONG_PTR uiExportRVA;
	ULONG_PTR uiExportSection;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiNumArray;
	ULONG_PTR uiFuncArray;
	ULONG_PTR uiNumOfNames;

	ULONG_PTR uiOldFlink = uiLdrFlink;
	while (uiLdrFlink) {
		//指向当前模块名称,unicode string
		uiDllName = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiLdrFlink)->BaseDllName.Buffer;
		//模块名称长度
		uiDllLength = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiLdrFlink)->BaseDllName.Length;
		//DllHash清零
		dwLdrDllHash = 0;

		ComputeHash(uiDllName, uiDllLength, &dwLdrDllHash);

		//Hash匹配到以后
		if (dwLdrDllHash == dwDllHash) {
			uiBaseAddr = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiLdrFlink)->DllBase;
			//获取RVA
			uiExportRVA = GetDataDirectoryRVA((PIMAGE_DOS_HEADER)uiBaseAddr, IMAGE_DIRECTORY_ENTRY_EXPORT);

			//定位到导出表
			uiExportSection = uiBaseAddr + uiExportRVA;

			//获取EAT，导出名称表
			uiNameArray = uiBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uiExportSection)->AddressOfNames;

			//获取ENT，导出序号表，最终通过序号获取函数地址
			uiNumArray = uiBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uiExportSection)->AddressOfNameOrdinals;

			//获取函数地址表
			uiFuncArray = uiBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uiExportSection)->AddressOfFunctions;

			//获取个数
			uiNumOfNames = uiBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uiExportSection)->NumberOfNames;

			//遍历寻找函数名
			for (int i = 0; i < uiNumOfNames; i++) {
				if (!strcmp((char*)(uiBaseAddr + ((PDWORD)uiNameArray)[i]), "LoadLibrary")) {
					int a = 1;
				}
				dwLdrFuncHash = hash((char*)(uiBaseAddr + ((PDWORD)uiNameArray)[i]));

				if (dwLdrFuncHash == dwFuncHash) {
					uiResult = uiBaseAddr + ((PDWORD)uiFuncArray)[((PWORD)uiNumArray)[i]];
					goto End;
				}
			}
		}

		uiLdrFlink = DEREF(uiLdrFlink);

		//循环一圈没找到后旧退出
		if (uiOldFlink == uiLdrFlink)
			break;
	}
	End:
	return uiResult;
}