//�Ȳ����ú�������û���޸�ջָ�룬Ҳû��ʹ�� SEH �ĺ����ͽ�����Ҷ��������
#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>

// x64 SEH ������ջ���������쳣��ͨ��ִ��û������Ч�ʸ�
// ÿ����Ҷ�������ٶ�Ӧһ�� RUNTIME FUCNTION�ṹ��
//Ҷ�������ʹ����SEH, Ҳ���Ӧ RUNTIME FUCNTION�ṹ��
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
