#include"ReflectiveLoader.h"
//����DllMain�������
#define	REFLECTIVELOADER_NO_PARAMETER

//Copy From https://github.com/stephenfewer/ReflectiveDLLInjection 

//ͨ��intrinsic�ؼ��֣��������������Ż���������������ֱ�ӵ��ú���
#pragma intrinsic(_ReturnAddress)

//__declspec(noinline) ����������
//_ReturnAddress���ص�ǰ�������ִ�е�ַ
DECLSPEC_NOINLINE ULONG_PTR	ReturnFuncAddres (VOID){
	//Call _ReturnAddress
	//mov	[],rax -> rax=��һ�еĵ�ַ
	return (ULONG_PTR)_ReturnAddress();
}


//���嶨�����
#ifdef REFLECTIVELOADER_NO_PARAMETER
DLLEXPORT	ULONG_PTR	WINAPI ReflectiveLoader(VOID)
#else
//���������
DLLEXPORT	ULONG_PTR	WINAPI ReflectiveLoader(LPVOID	lpParameter)
#endif // !REFLECTIVELOADER_NO_PARAMETER
{

	ULONG_PTR uiDosHeader;

	//��ȡCaller������ַ��,�ڴ�������ѰIMAGE_DOS_HEADER,��λ�ļ�λ��
	ULONG_PTR uiCallerAddr;
	//step0 ��ȡDosͷ��	
	

	

	//step8 Return DllMain	Address
	return	uiBaseAddr;
}