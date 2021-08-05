//https://www.cnblogs.com/schips/p/common-design-pattern-about-cpp.html

#include<iostream>
#include <mutex>

//单例类只能由一个实例化对象。
//单例类必须自己提供一个实例化对象。
//单例类必须提供一个可以访问唯一实例化对象的接口。

class Singleton {
public:
	static Singleton* getInstance();
	~Singleton() {};
private:
	Singleton() {};
	Singleton(const Singleton&) = delete; //明确拒赋值构造
	Singleton& operator = (const Singleton&) = delete; //明确拒绝等号运算符重载

	static  Singleton* m_pSingleton; //静态成员
};


////lazy initialization  非线程安全
// Singleton* Singleton::m_pSingleton = NULL;
//Singleton* Singleton::getInstance() {
//	if (m_pSingleton == NULL) {
//		m_pSingleton = new Singleton;
//	}
//	return m_pSingleton;
//}

////lazy initialization 线程安全
// Singleton* Singleton::m_pSingleton = NULL;
//std::mutex mt;
//Singleton* Singleton::getInstance() {
//	if (m_pSingleton == NULL) {
//		mt.lock();
//		if (m_pSingleton == NULL) {
//			m_pSingleton = new Singleton();
//		}
//		mt.unlock();
//	}
//	return m_pSingleton;
//}

//early initialization 线程安全
Singleton* Singleton::m_pSingleton = new Singleton();
Singleton* Singleton::getInstance() {
	return m_pSingleton;
}



int main() {
	Singleton* s1 = Singleton::getInstance();
	Singleton* s2 = Singleton::getInstance();
	printf("%p,%p\n", s1, s2);

	delete s1;

	return 0;
}