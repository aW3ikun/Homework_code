#ifndef _REFLECTIVELOADER_H_
#define _REFLECTIVELOADER_H_

#include"../../PE/新增加一个节/pe.h"
#include <intrin.h>

#define DLL_QUERY_HMODULE		6

#define DLLEXPORT	 __declspec( dllexport )

typedef ULONG_PTR (WINAPI* REFLECTIVELOADER)( VOID );
typedef BOOL (WINAPI* DLLMAIN)( HINSTANCE, DWORD, LPVOID );

HINSTANCE hAppInstance;

#endif // !_REFLECTIVELOADER_H_
