//抽象工厂模式 提供创建一系列相关或相互依赖对象的接口，而无需指定它们具体的类。
//当存在多个产品系列，而客户端只使用一个系列的产品时，可以考虑使用抽象工厂模式。
// https://www.cnblogs.com/schips/p/common-design-pattern-about-cpp.html
/*
* 关键代码：在一个工厂里聚合多个同类产品。
* 以下代码以白色衣服和黑色衣服为例，白色衣服为一个产品系列，黑色衣服为一个产品系列。白色上衣搭配白色裤子，   黑色上衣搭配黑色裤字。每个系列的衣服由一个对应的工厂创建，这样一个工厂创建的衣服能保证衣服为同一个系列。
*/
#include<iostream>
using namespace std;

//抽象上衣类
class Coat {
public: 
	virtual const string& color() = 0;
};

//黑色上衣类
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

//白色上衣类
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

//抽象裤子类
class Pants {
public:
	virtual const string& color() = 0;
};
//黑色裤子类
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

//白色裤子类
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


//抽象工厂类，提供衣服创建接口
class Factory {
public:
	virtual Coat* createCoat() = 0;
	virtual Pants* createPants() = 0;
};

//创建白色衣服的工厂类，具体实现创建白色上衣和白色裤子的接口
class WhiteFactory :public Factory {
public:
	Coat* createCoat() override {
		return new WhiteCoat();
	}
	Pants* createPants() override {
		return new WhitePants();
	}
};

//创建黑色衣服的工厂类，具体实现创建黑色上衣和黑色裤子的接口
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