//https://www.cnblogs.com/schips/p/common-design-pattern-about-cpp.html

#include<iostream>
using namespace std;

//单例类只能由一个实例化对象。
//单例类必须自己提供一个实例化对象。
//单例类必须提供一个可以访问唯一实例化对象的接口。

class Singleton {
public:
	static Singleton* getInstance();
	~Singleton() {};

private:
	static int getCount();
	Singleton() {};
	Singleton(const Singleton&) = delete; //明确拒赋值构造
	Singleton& operator = (const Singleton&) = delete; //明确拒绝等号运算符重载

	static  Singleton* m_pSingleton; //静态成员
};

Singleton*  Singleton::m_pSingleton = NULL;

int main() {
	return 0;
}