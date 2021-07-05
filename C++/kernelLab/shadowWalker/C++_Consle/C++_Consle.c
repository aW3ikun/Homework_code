#include<stdio.h>
#include<stdlib.h>
#include<windows.h>

#define PTE(x)	((DWORD *)(0xC0000000 + ((x >> 12) << 3)))  
#define PDE(x)	((DWORD *)(0xC0060000 + ((x >> 21) << 3)))

#define K_ESP 0x8003f3f0 //error_code
#define K_ESP_4 0x8003f3f4 //eip
#define K_TARGET_CR3 0x8003f3e0
#define K_CR2 0x8003f3e4

#define K_REAL_PTE0	0x8003f3d0 
#define K_REAL_PTE1 0x8003f3d4 
#define K_FAKE_PTE0 0x8003f3d8
#define K_FAKE_PTE1 0x8003f3dc


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

#pragma section("mydata",read,write) 
__declspec(allocate("mydata")) DWORD FakePage[1024]; //0x41c000
       
//0x0401080
//__declspec(naked)  直接作为汇编使用
void __declspec(naked) IdtEntry1()
{
	*(DWORD*)K_REAL_PTE0 = PTE(0x412000)[0];
	*(DWORD*)K_REAL_PTE1 = PTE(0x412000)[1];
	*(DWORD*)K_FAKE_PTE0 = PTE(0x41c000)[0];
	*(DWORD*)K_FAKE_PTE1 = PTE(0x41c000)[1];

	PTE(0x412000)[0] = 0x0;
	PTE(0x412000)[1] = 0x0;

	__asm {
		mov eax, cr3
		mov ds : [K_TARGET_CR3] , eax

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
	__asm {
		jmp L
		ret	//00412018
	}
L:
	if ((DWORD)IdtEntry1 != 0x0401080) {
		printf("wrong addr：%p\n", IdtEntry1);
		system("pause");
		exit(-1);
	}
	//使34行声明有效
	FakePage[0] = 0;
	go();
	int i = 0;
	while(1){

		printf("%d\n", i++);
		Sleep(1000);
	}

	system("pause");
}
