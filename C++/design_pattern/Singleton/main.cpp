//https://www.cnblogs.com/schips/p/common-design-pattern-about-cpp.html

#include<iostream>
using namespace std;

//������ֻ����һ��ʵ��������
//����������Լ��ṩһ��ʵ��������
//����������ṩһ�����Է���Ψһʵ��������Ľӿڡ�

class Singleton {
public:
	static Singleton* getInstance();
	~Singleton() {};

private:
	static int getCount();
	Singleton() {};
	Singleton(const Singleton&) = delete; //��ȷ�ܸ�ֵ����
	Singleton& operator = (const Singleton&) = delete; //��ȷ�ܾ��Ⱥ����������

	static  Singleton* m_pSingleton; //��̬��Ա
};

Singleton*  Singleton::m_pSingleton = NULL;

int main() {
	return 0;
}