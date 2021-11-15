#include<iostream>
using namespace std;


class NewBase {
	public:
	//void Go(){ cout << "this is Base  " << endl; };
	virtual void Go( ) = 0;
	public:
	int m_b;
	int m_a;
};
class NewSub:public NewBase
{
	public:
	//void Go( ) { cout << "this is NewSub  " << endl; }
	void Go( ) { m_c += 1; }
	public:
	int m_c;

};


//class VirtualBase
//{
//	//Pure	virtual	functions
//	public:
//	VirtualBase( )
//	{
//		m_a = 1;
//	}
//	virtual void Demon( ) = 0;
//	virtual	void Base( ) { cout << "this is VirtualBase Base()" << endl; }
//	virtual void Base2( ) { cout << "this is VirtualBase  Base2()" << endl; };
//	private:
//	int m_a;
//};
//class VirtualBase2
//{
//	//Pure	virtual	functions
//	public:
//	VirtualBase2( )
//	{
//		m_b = 1;
//	}
//	virtual void Demon( ) = 0;
//	virtual	void Base( ) { cout << "this is VirtualBase2 Base()" << endl; }
//	virtual void Base2( ) { cout << "this is VirtualBase2  Base2()" << endl; };
//	private:
//	int  m_b;
//};
//
//class SubVirtual :public VirtualBase {
//	public:
//
//	SubVirtual( )
//	{
//		m_c = 2;
//	}
//	void Demon( ) { cout << "SubVirtual Demon" << endl; };
//	//void Base( ) { cout << "this is SubVirtual class" << endl; };
//	void Go( ) { cout << "this is SubVirtual4 GO" << endl; }
//	private:
//	int  m_c;
//
//};
//class SubVirtual2 :public VirtualBase {
//	public:
//	SubVirtual2( )
//	{
//		m_d = 3;
//	}
//	void Demon( ) { cout << "SubVirtual2 Demon" << endl; };
//	void Base( ) { cout << "this is SubVirtual2 class" << endl; };
//	private:
//	int  m_d;
//};
//
//class SubVirtual3 :public SubVirtual2 {
//	public:
//	SubVirtual3( )
//	{
//		m_e = 4;
//	}
//	void Base( ) { cout << "this is SubVirtual3 class" << endl; };
//	private:
//	int  m_e;
//};
//
//class SubVirtual4 :public VirtualBase, public VirtualBase2 {
//	public:
//	SubVirtual4( )
//	{
//		m_f = 4;
//	}
//	void Demon( ) { cout << "SubVirtual4 class" << endl; }
//	void Base( ) { cout << "this is SubVirtual4 class" << endl; };
//
//	private:
//	int m_f;
//};
//
//void call(VirtualBase* vb)
//{
//	vb->Demon( );
//	vb->Base( );
//	vb->Base2( );
//}
//

int main(int argc, char* argv[])
{

	NewSub	sub;
	sub.m_b = 0;
	sub.m_a = 1;
	auto *pt = &sub;
	pt->m_c = 2;
	
	sub.Go( );
	pt->Go( );

	//VirtualBase* sv = new	SubVirtual( );
	//SubVirtual* sub = new	SubVirtual( );
	//VirtualBase* sv = sub;
	//VirtualBase* sv2 = new	SubVirtual2( );
	//VirtualBase* sv3 = new	SubVirtual3( );
	//VirtualBase* sv4 = new	SubVirtual4( );
	//sub->Go( );



	//call(sv);
	//cout << "======================" << endl;
	//call(sv2);
	//cout << "======================" << endl;
	//call(sv3);
	//cout << "======================" << endl;
	//call(sv4);


	system("pause");
	return 0;
}


