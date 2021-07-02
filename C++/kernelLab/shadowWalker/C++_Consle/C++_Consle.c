#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define K_ESP 0x8003f3f0 //error_code
#define K_ESP_4 0x8003f3f4 //eip
#define K_TARGET_CR3 0x8003f3e0 
#define K_CR2 0x8003f3e4

//KiTrap0E
// error_code
// eip
// cs
// eflags
// esp
// ss

//After Figure 6-10

DWORD g_esp;
DWORD g_esp_4;
DWORD g_cr2; //产生页保护的虚拟地址
//0x0401080
//__declspec(naked)  直接作为汇编使用
void __declspec(naked) IdtEntry1()
{
	__asm {

		mov eax, cr3
		mov ds : [K_TARGET_CR3] , eax

		mov eax, ds : [K_ESP]
		mov g_esp, eax

		mov eax, ds : [K_ESP_4]
		mov g_esp_4, eax

		mov eax, ds : [K_CR2]
		mov g_cr2, eax

		xor eax, eax
		mov ds : [K_ESP_4] , eax

		iretd
	}
}

#pragma code_seg(".my_code") __declspec(allocate(".my_code ")) void go();
#pragma code_seg(".my_code") __declspec(allocate(".my_code ")) void main();
void go() {
	__asm {
		int 0x20
	}
}
//eq 8003f500 0040ee00`00081080
void  main() {
	if ((DWORD)IdtEntry1 != 0x0401080) {
		printf("wrong addr：%p\n", IdtEntry1);
		system("pause");
		exit(-1);
	}
	while(1){
		go();
		if (g_esp_4)
			printf("error_code: %p eip: %p  cr2: %p\n", g_esp, g_esp_4, g_cr2);
		Sleep(1000);
	}

	system("pause");
}
