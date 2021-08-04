//���������һ��һ�Զ��������ϵ����һ�������״̬�����ı�ʱ��
//�������������Ķ���Ҫ�õ�֪ͨ���Զ����¡�

//�ؼ����룺��Ŀ����������һ��ArrayList����Ź۲����ǡ�

#include<iostream>
#include<list>
#include<memory>

using namespace std;

class View;

//���۲��߳����� 
class DataModel {
public:
	virtual ~DataModel() {};
	virtual void addView(View* view) = 0;
	virtual void removeView(View* view) = 0;
	virtual void notify() = 0;
};

//�۲��߳����� 
class View {
public:
	virtual ~View() {
		cout << "~View()" << endl;
	}
	virtual void update() = 0;
	virtual void setViewName(const string& name) = 0;
	virtual const string& name() = 0;
};

//����ı��۲���
class IntDataModel :public DataModel {
public:
	~IntDataModel() {
		m_pViewList.clear();
	}
	virtual void addView(View* view) override {
		shared_ptr<View> temp(view);
		auto iter = find(m_pViewList.begin(), m_pViewList.end(), temp);
		if (iter == m_pViewList.end()) {
			m_pViewList.push_front(temp);
		}
		else {
			cout << "View already exists " << endl;
		}
	}
	void removeView(View* view) override {
		auto iter = m_pViewList.begin();
		for (; iter != m_pViewList.end(); iter++) {
			if ((*iter).get() == view) {
				m_pViewList.erase(iter);
				cout << "remove view" << endl;
				return;
			}
		}
	}
	void notify() override {
		auto iter = m_pViewList.begin();
		for (; iter != m_pViewList.end(); iter++) {
			(*iter).get()->update();
		}
	}
private:
	list<shared_ptr<View>> m_pViewList;
};

// ����Ĺ۲���
class TableView : public View {
public:
	TableView():m_name("unknow") {};
	TableView(const string& name) : m_name(name) {}
	~TableView() { 
		cout << "~TableView(): " << m_name.data() << endl; 
	}
	void update() {
		cout << m_name.data() << "update" << endl;
	}
	void setViewName(const string& name) {
		m_name = name;
	}
	const string& name() {
		return m_name;
	}
private:
	string m_name;
};

int main() {
	View* v1 = new TableView("TableView1");
	View* v2 = new TableView("TableView2");
	View* v3 = new TableView("TableView3");
	View* v4 = new TableView("TableView4");

	IntDataModel* model = new IntDataModel;
	model->addView(v1);
	model->addView(v2);
	model->addView(v3);
	model->addView(v4);

	model->notify();

	cout << "-------------\n" << endl;
	model->removeView(v1);

	model->notify();

	delete model;
	model = nullptr;

	system("pause");
	return 0;
}