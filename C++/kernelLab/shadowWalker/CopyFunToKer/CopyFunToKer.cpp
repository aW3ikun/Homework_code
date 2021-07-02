#include<stdio.h>
#include<stdlib.h>
#include<windows.h>


#define K_ESP 0x8003f3f0
#define K_ESP_4 0x8003f3f4
#define K_TARGET_CR3 0x8003f3e0
#define K_CR2 0x8003f3e4

//target 0x8003f120
//0x8053e545
//code = 0x0041a7b0
//char code[64] = { 0xB9,0x23,0x00,0x00,0x00,0xe9,0x16,0xF4,0x4f,0x00 };
void JmpTarget();
int i;
char* p;
//0x0401080
void __declspec(naked) IdtEntry1()
{
	p = (char*)0x8003f130;
	for (i = 0; i < 256; i++)
	{
		*p = ((char*)JmpTarget)[i];
		p++;
	}
	__asm {
		mov eax,0xffffffff
		mov ds:[K_TARGET_CR3],eax

		mov eax,cr0
		and eax,~0x10000
		mov cr0,eax
		
		mov ds : [0x80541450] , 0x68
		mov dword ptr ds : [0x80541451] , 0x8003f130
		mov word ptr ds : [0x80541455] , 0x90C3

		xor eax, eax
		mov ds : [K_ESP] , eax
		mov ds : [K_ESP_4] , eax
		mov ds : [K_CR2] , eax

		//将 Cr0.WP置为1 启动写保护
		mov eax,cr0
		or eax,0x10000
		mov eax,cr0
		
		iretd
	}
}
void __declspec(naked) JmpTarget() {
	__asm {
		push eax
		mov eax, cr3
		cmp eax, ds: [K_TARGET_CR3]
		jnz End

		mov eax, [esp + 4]
		mov ds : [K_ESP] , eax
		mov eax, [esp + 8]
		mov ds : [K_ESP_4] , eax
		mov eax, cr2
		mov ds : [K_CR2] , eax

		End :
		pop eax
			mov     word ptr[esp + 2], 0
			push 0x80541457
			ret
	}
}
void go() {
	__asm int 0x20

}
//eq 8003f500 0040ee00`00081080
int main() {
	if ((DWORD)IdtEntry1 != 0x0401080) {
		printf("wrong addr：%p\n", IdtEntry1);
		exit(-1);
	}
	go();
	//printf("g_pool: %p\n", g_pool);
	system("pause");
}