#include<iostream>
using namespace std;

class VirtualBase
{
	//Pure	virtual	functions
	public:
	VirtualBase( )
	{
		x = 1;
	}
	virtual void Demon( ) = 0;
	virtual	void Base( ) { cout << "this is father class" << endl; }
	virtual void Base2( ) { cout << "this is father2 class" << endl; };
	private:
	int x;
};

class SubVirtual :public VirtualBase {
	public:

	SubVirtual( )
	{
		y = 2;
	}
	void Demon( ) { cout << "SubVirtual Demon" << endl; };
	//void Base( ) { cout << "this is SubVirtual class" << endl; };
	private:
	int y;

};
class SubVirtual2 :public VirtualBase {
	public:
	SubVirtual2( )
	{
		z = 3;
	}
	void Demon( ) { cout << "SubVirtual2 Demon" << endl; };
	void Base( ) { cout << "this is SubVirtual2 class" << endl; };
	private:
	int z;
};

class SubVirtual3 :public SubVirtual2 {
	public:
	SubVirtual3( )
	{
		m = 4;
	}
	void Base( ) { cout << "this is SubVirtual3 class" << endl; };
	private:
	int m;
};

void call(VirtualBase* vb)
{
	vb->Demon( );
	vb->Base( );
	vb->Base2( );
}


int main(int argc, char* argv[])
{

	VirtualBase* sv = new	SubVirtual( );
	VirtualBase* sv2 = new	SubVirtual2( );
	VirtualBase* sv3 = new	SubVirtual3( );

	call(sv);
	cout << "======================" << endl;
	call(sv2);
	cout << "======================" << endl;
	call(sv3);

	type_info

	system("pause");
	return 0;
}