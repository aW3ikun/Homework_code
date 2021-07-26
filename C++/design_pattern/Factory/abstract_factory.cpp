//���󹤳�ģʽ �ṩ����һϵ����ػ��໥��������Ľӿڣ�������ָ�����Ǿ�����ࡣ
//�����ڶ����Ʒϵ�У����ͻ���ֻʹ��һ��ϵ�еĲ�Ʒʱ�����Կ���ʹ�ó��󹤳�ģʽ��
// https://www.cnblogs.com/schips/p/common-design-pattern-about-cpp.html
/*
* �ؼ����룺��һ��������ۺ϶��ͬ���Ʒ��
* ���´����԰�ɫ�·��ͺ�ɫ�·�Ϊ������ɫ�·�Ϊһ����Ʒϵ�У���ɫ�·�Ϊһ����Ʒϵ�С���ɫ���´����ɫ���ӣ�   ��ɫ���´����ɫ���֡�ÿ��ϵ�е��·���һ����Ӧ�Ĺ�������������һ�������������·��ܱ�֤�·�Ϊͬһ��ϵ�С�
*/
#include<iostream>
using namespace std;

//����������
class Coat {
public: 
	virtual const string& color() = 0;
};

//��ɫ������
class BlackCoat : public Coat {
public:
	BlackCoat() :Coat(), m_strColor("Black Coat") {

	}
	const string& color() override {
		cout << m_strColor.data() << endl;
		return m_strColor;
	}
private:
	string m_strColor;
};

//��ɫ������
class WhiteCoat : public Coat {
public:
	WhiteCoat() :Coat(), m_strColor("Black Coat") {

	}
	const string& color() override {
		cout << m_strColor.data() << endl;
		return m_strColor;
	}
private:
	string m_strColor;
};

//���������
class Pants {
public:
	virtual const string& color() = 0;
};
//��ɫ������
class BlackPants : public Pants {
public:
	BlackPants() :Pants(), m_strColor("Black Pants") {

	}
	const string& color() override {
		cout << m_strColor.data() << endl;
		return m_strColor;
	}

private:
	string m_strColor;
};

//��ɫ������
class WhitePants : public Pants {
public:
	WhitePants() :Pants(), m_strColor("Black Pants") {

	}
	const string& color() override {
		cout << m_strColor.data() << endl;
		return m_strColor;
	}

private:
	string m_strColor;
};


//���󹤳��࣬�ṩ�·������ӿ�
class Factory {
public:
	virtual Coat* createCoat() = 0;
	virtual Pants* createPants() = 0;
};

//������ɫ�·��Ĺ����࣬����ʵ�ִ�����ɫ���ºͰ�ɫ���ӵĽӿ�
class WhiteFactory :public Factory {
public:
	Coat* createCoat() override {
		return new WhiteCoat();
	}
	Pants* createPants() override {
		return new WhitePants();
	}
};

//������ɫ�·��Ĺ����࣬����ʵ�ִ�����ɫ���ºͺ�ɫ���ӵĽӿ�
class BlackFactory :public Factory {
public:
	Coat* createCoat() override {
		return new BlackCoat();
	}
	Pants* createPants() override {
		return new BlackPants();
	}
};
int main() {
	Factory* whitefactory = new WhiteFactory();
	whitefactory->createCoat()->color();
	whitefactory->createPants()->color();

	Factory* blackfactory = new BlackFactory();
	blackfactory->createCoat()->color();
	blackfactory->createPants()->color();

	delete whitefactory;
	whitefactory = nullptr;
	delete blackfactory;
	blackfactory = nullptr;

	}