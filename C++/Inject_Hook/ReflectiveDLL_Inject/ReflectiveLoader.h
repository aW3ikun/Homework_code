#ifndef _REFLECTIVELOADER_H_
#define _REFLECTIVELOADER_H_

#include"../../PE/������һ����/pe.h"
#include <intrin.h>

#define DLLEXPORT	 __declspec( dllexport )

typedef ULONG_PTR (WINAPI* REFLECTIVELOADER)( VOID );
typedef BOOL (WINAPI* DLLMAIN)( HINSTANCE, DWORD, LPVOID );

#endif // !_REFLECTIVELOADER_H_
