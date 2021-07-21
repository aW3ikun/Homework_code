//https://www.cnblogs.com/schips/p/common-design-pattern-about-cpp.html

#include<iostream>
#include <mutex>

//������ֻ����һ��ʵ��������
//����������Լ��ṩһ��ʵ��������
//����������ṩһ�����Է���Ψһʵ��������Ľӿڡ�

class Singleton {
public:
	static Singleton* getInstance();
	~Singleton() {};
private:
	Singleton() {};
	Singleton(const Singleton&) = delete; //��ȷ�ܸ�ֵ����
	Singleton& operator = (const Singleton&) = delete; //��ȷ�ܾ��Ⱥ����������

	static  Singleton* m_pSingleton; //��̬��Ա
};


////lazy initialization  ���̰߳�ȫ
// Singleton* Singleton::m_pSingleton = NULL;
//Singleton* Singleton::getInstance() {
//	if (m_pSingleton == NULL) {
//		m_pSingleton = new Singleton;
//	}
//	return m_pSingleton;
//}

////lazy initialization �̰߳�ȫ
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

//early initialization �̰߳�ȫ
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