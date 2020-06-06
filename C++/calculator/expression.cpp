#include<iostream>
#include<stack>
#include<string>
using namespace std;

// 42 47 43 45
//'*','/','+','-'
stack <char> s1;
stack <char> s2;

void s1_2_s2() { //s1移动栈顶到s2
	char str = s1.top();
	s1.pop();
	s2.push(str);
}
string print_stack() {	//逆序打栈列表
	string a;
	stack<char> s3;
	while (!s2.empty()) {
		a += s2.top();
		s3.push(s2.top());
		s2.pop();
	}
	string b(a.rbegin(), a.rend());
	for (size_t i = 0; i < s3.size(); i++)
	{
		s2.push(s3.top());
		s3.pop();
	}
	cout << b << endl;
	return b; //aΪ������ַ���
}
void push_func(char str, int num_1) { //判断压入

	if (s1.empty() || s1.top() == '(')
	{
		s1.push(str);
	}
	else
	{
		int num_2 = 1;
		if (s1.top() == '*' || s1.top() == '/')
			num_2 = 2;
		if (num_1 > num_2)
			s1.push(str);
		else {
			s1_2_s2();
			push_func(str, num_1);
		}
	}

}
string  function(string expression) { //后缀表达式计算
	int stack_size = expression.size();
	for (int i = 0; i < stack_size; i++)
	{
		char a = expression[i];
		int b = int(a);
		switch (b)
		{
		case 43:    //'+'
		case 45:    // '-'
			push_func(a, 1);
			break;
		case 42:    //'*'
		case 47:    //'/'
			push_func(a, 2);
			break;
		case 40:    //'('
			s1.push(a);
			break;
		case 41:   //')'
			while (s1.top() != '(') {
				if (s1.top() == ')')
					s1.pop();
				s1_2_s2();
			}
			s1.pop();
			break;
		default:
			s2.push(a);
			break;
		}
	}
	while (!s1.empty())
	{
		s1_2_s2();
	}
	string result = print_stack();
	return result;
}
double  calc(string a) {	//计算后缀表达式
	stack<double> num;
	int stack_size = a.size();
	for (int i = 0; i < stack_size; i++)
	{
		wchar_t chr = a[i];
		int b = int(chr);
		double i1 = 0;
		double i2 = 0;
		switch (b)
		{
		case 43:    //'+'
			i2 = num.top();
			num.pop();
			i1 = num.top();
			num.pop();
			num.push(i1 + i2);
			break;
		case 45:    // '-'
			i2 = num.top();
			num.pop();
			i1 = num.top();
			num.pop();
			num.push(i1 - i2);
			break;
		case 42:    //'*'
			i2 = num.top();
			num.pop();
			i1 = num.top();
			num.pop();
			num.push(i1 * i2);
			break;
		case 47:    //'/'
			i2 = num.top();
			num.pop();
			i1 = num.top();
			num.pop();
			if (i2 == 0) {
				cout << "����Ϊ0, �˳�" << endl;
				exit(0);
			}
			num.push(i1 / i2);
			break;
		default:
			num.push(double(chr - '0'));
			break;
		}
	}
	return num.top();
}

int main(int argc, char* argv[]) {
	string str = argv[1];
	string a =  function(str);
	cout << calc(a);
	return 0;

}