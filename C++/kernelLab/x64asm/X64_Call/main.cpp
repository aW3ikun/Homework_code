#include<cstdio>
#include<stdlib.h>
#include<Windows.h>
//https://space.bilibili.com/37877654/channel/detail?cid=89318&ctype=0
//叶函数 不在内部调用任何外部函数
extern "C" {

	ULONG64 x;
	void asm_func();
	void func_leaf() {
		;
	}
	void func(ULONG a1,  ULONG a2, ULONG a3, ULONG a4, ULONG a5) {
		printf("a1: %p\n", a1);
		printf("a1: %p\n", a2);
		printf("a1: %p\n", a3);
		printf("a1: %p\n", a4);
		printf("a1: %p\n", a5);
		//func_leaf();
	}
}
int main(int argc,char** argv) {
	//for (int i = 0; i < argc; i++) {
	//	printf("%s\n", argv[i]);
	//}
	asm_func();
	printf("hello x64\n");
	system("pause");
	//func_leaf();
	return 0;
}


//r
//$ ==> arg1
//$ + 8           arg2
//$ + 10          arg3
//$ + 18          arg4
//$ + 20          var i = 0
//$ + 28 < -- - padding
//$ + 30          rdi
//$ + 38          r
//$ + 40          ecx argc
//$ + 48          rdx argv
//$ + 50
//$ + 58

