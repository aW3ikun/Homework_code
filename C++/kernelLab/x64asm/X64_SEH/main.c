//既不调用函数、又没有修改栈指针，也没有使用 SEH 的函数就叫做“叶函数”。
#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>

// x64 SEH 不基于栈，不发生异常和通常执行没有区别（效率高
// 每个非叶函数至少对应一个 RUNTIME FUCNTION结构体
//叶函数如果使用了SEH, 也会对应 RUNTIME FUCNTION结构体
int filter() {
	printf("filter\n");
	return 1;
}

void exc() {
	int x = 0;
	int y = x / x;
}

typedef struct _UNWIND_INFO {
	byte Version : 3;
	byte Flags : 5;
} ssss;
int main() {
	ssss s1;
	s1.Flags = 3;
	s1.Version = 5;

	__try {
		__try {
			exc();
		}
		__finally {
			printf("111\n");
		}
	}
	__except (filter()) {
		printf("222\n");
	}
	system("pause");
	return 0;
}
//https://www.pediy.com/kssd/pediy12/142371.html
//https://www.bilibili.com/video/BV1tJ411M7kd
