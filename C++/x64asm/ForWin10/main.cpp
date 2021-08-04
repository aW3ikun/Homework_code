#include<cstdio>
#include<stdlib.h>
#include<Windows.h>
// 固定机制，关增量链接
//int 21h fffff803`4f25b210  4c9f8e00`0010c388 00000000`fffff803
//eq fffff803`4f25b210 4000ee00`001010e0
//eq fffff803`4f25b218 00000000`00000001
//r cr4 = 0x270678

extern "C" void IdtEntry();
extern "C" void go();
extern "C" ULONG64 x;
ULONG64 x;

int main() {
	if ((ULONG64)IdtEntry != 0x00000001400010E0) {
		printf("wrong IdtEntry at %p\n", IdtEntry);
		system("pause");
		exit(-1);
	}
	go();
	printf("%p\n",x);
	system("pause");
	return 0;
}