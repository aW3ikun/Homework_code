//用简单工厂模式，我们只需要知道具体的产品型号就可以创建一个产品。
// 一个工厂方法创建不同类型的对象。
// https://www.cnblogs.com/schips/p/common-design-pattern-about-cpp.html
#include<iostream>
using namespace std;

//定义产品类型信息
typedef enum {
	Tank_Type_56,
	Tank_Type_96,
	Tand_Type_Num
}Tank_Type;

//抽象产品类
class Tank {
public:
	virtual const string& type() = 0;
};

//具体的产品类
class Tank56 : public Tank
{
public:
	Tank56() :Tank(), m_strType("Tank56") {

	}
	//在派生类的成员函数中使用override时，如果基类中无此函数，或基类中的函数并不是虚函数，会报错
	const string& type()override {
		cout << m_strType.data() << endl;
		return m_strType;
	}
private:
	string m_strType;
};

//具体的产品类
class Tank96 : public Tank
{
public:
	Tank96() :Tank(), m_strType("Tank96")
	{
	}
	const string& type() override
	{
		cout << m_strType.data() << endl;
		return m_strType;
	}
private:
	string m_strType;
};

class TankFactory {
public:
	Tank* createTank(Tank_Type type) {
		switch (type) {
		case Tank_Type_56:
			return new Tank56();
		case Tank_Type_96:
			return new Tank96();
		default:
			return nullptr;
		}
		
	}
};

int main() {
	TankFactory* factory = new TankFactory();
	Tank* tank56 = factory->createTank(Tank_Type_56);
	tank56->type();
	Tank* tank96 = factory->createTank(Tank_Type_96);
	tank96->type();

	delete tank96;
	tank96 = nullptr;
	delete tank56;
	tank56 = nullptr;
	delete factory;
	factory = nullptr;
 	return 0;
}