#include<cstdio>
#include<stdlib.h>
#include<Windows.h>

extern "C" void func();

int main() {
	func();
	printf("hello x64\n");
	system("pause");
	return 0;
}