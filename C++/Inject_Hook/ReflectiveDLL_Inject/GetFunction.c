#include"GetFunction.h"

//���Ƽ���
__forceinline DWORD ror(DWORD d) {
	return _rotr(d, HASH_KEY);
}

//���㺯����hash
__forceinline DWORD hash(char* c) {
	register	DWORD h = 0;
	do {
		h = ror(h);
		h += *c;
	} while (*++c);

	return h;
}

//��ȡpeb��ַ
inline ULONG_PTR GetPeb() {
#ifdef _WIN64
	return  (ULONG_PTR)__readgsqword(0x60);
#else
	return (ULONG_PTR)__readfsdword(0x30);
#endif // WIN_X64
}

//��ȡLdr��ַ
inline ULONG_PTR GetLdr(ULONG_PTR uiPebAddr) {
	return (ULONG_PTR)(((PPEB)uiPebAddr)->Ldr);
}

//ȫ��תΪ��д��Ȼ��hash����
inline VOID ComputeHash(ULONG_PTR	uiDllName, ULONG_PTR	uiDllLength, PDWORD	uiDllHash) {
	if (uiDllName == NULL)
		return;
	do {
		*uiDllHash = ror((DWORD)*uiDllHash);

		//��дת��
		if (*(BYTE*)uiDllName >= 'a')
			*uiDllHash += (*(BYTE*)uiDllName) - 0x20;
		else
			*uiDllHash += (*(BYTE*)uiDllName);
		uiDllName++;
	} while (--uiDllLength);
}

//��ȡ�ض�������ַ
ULONG_PTR GetFunction(DWORD dwDllHash, DWORD dwFuncHash) {
	//���صĵ�ַ
	ULONG_PTR	uiResult = 0;

	ULONG_PTR	uiPebAddr = GetPeb();
	ULONG_PTR	uiLdrAddr = GetLdr(uiPebAddr);
	ULONG_PTR	uiLdrFlink = (ULONG_PTR)((PPEB_LDR_DATA)uiLdrAddr)->InMemoryOrderModuleList.Flink;
	//DLL�����Ϣ
	ULONG_PTR	uiDllName;
	ULONG_PTR	uiDllLength;
	ULONG_PTR	uiBaseAddr;
	DWORD		dwLdrDllHash;
	DWORD		dwLdrFuncHash;
	//������
	ULONG_PTR uiExportRVA;
	ULONG_PTR uiExportSection;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiNumArray;
	ULONG_PTR uiFuncArray;
	ULONG_PTR uiNumOfNames;

	ULONG_PTR uiOldFlink = uiLdrFlink;
	while (uiLdrFlink) {
		//ָ��ǰģ������,unicode string
		uiDllName = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiLdrFlink)->BaseDllName.Buffer;
		//ģ�����Ƴ���
		uiDllLength = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiLdrFlink)->BaseDllName.Length;
		//DllHash����
		dwLdrDllHash = 0;

		ComputeHash(uiDllName, uiDllLength, &dwLdrDllHash);

		//Hashƥ�䵽�Ժ�
		if (dwLdrDllHash == dwDllHash) {
			uiBaseAddr = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiLdrFlink)->DllBase;
			//��ȡRVA
			uiExportRVA = GetDataDirectoryRVA((PIMAGE_DOS_HEADER)uiBaseAddr, IMAGE_DIRECTORY_ENTRY_EXPORT);

			//��λ��������
			uiExportSection = uiBaseAddr + uiExportRVA;

			//��ȡEAT���������Ʊ�
			uiNameArray = uiBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uiExportSection)->AddressOfNames;

			//��ȡENT��������ű�����ͨ����Ż�ȡ������ַ
			uiNumArray = uiBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uiExportSection)->AddressOfNameOrdinals;

			//��ȡ������ַ��
			uiFuncArray = uiBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uiExportSection)->AddressOfFunctions;

			//��ȡ����
			uiNumOfNames = uiBaseAddr + ((PIMAGE_EXPORT_DIRECTORY)uiExportSection)->NumberOfNames;

			//����Ѱ�Һ�����
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

		//ѭ��һȦû�ҵ�����˳�
		if (uiOldFlink == uiLdrFlink)
			break;
	}
	End:
	return uiResult;
}