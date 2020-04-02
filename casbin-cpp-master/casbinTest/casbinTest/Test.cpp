#include "util.h"
#include "model.h"
#include "file-adapter.h"
#include "enforcer.h"
#include"Cparse/shunting-yard.h"
#include<algorithm>
#include <regex>

#include <iostream>
using namespace std;
void SplitTest();
void ArrayToStringTest();
void EscapeAssertionTest();
void RemoveCommentTest();
void DemoTest();
void DemoTest1();

int main()
{
	DemoTest();
	return 0;
}


void DemoTest()
{
	Model m = Model();
	m.AddDef("r", "r", "sub, obj, act");
	m.AddDef("p", "p", "sub, obj, act");
	m.AddDef("e", "e", "some(where (p.eft == allow))");
	m.AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act");

	Adapter* adapter = new FileAdapter("-------file------path-------");

	Enforcer e = Enforcer(m, adapter);

	vector<string> s = { "alice","data1","read" };
	vector<string> s1 = { "bob","data2","write" };

	e.model.AddPolicy("p", "p", s);
	e.model.AddPolicy("p", "p", s1);
	e.model.PrintPolicy();
	cout << e.enforce("", { "bob","data1","write" }) << endl;
	cout << e.enforce("", { "bob","data2","write" }) << endl;

}

void DemoTest1()
{

}

void SplitTest()
{
	string s = "1, 2, asd, qwe";
	vector<string> vs = Util::Split(s, ", ");
	for (string val : vs)
	{
		cout << val << endl;
	}
}

void ArrayToStringTest()
{
	vector<string> s = { "asd","qwe","3" };
	cout << Util::ArrayToString(s);
}

void EscapeAssertionTest()
{
	cout << Util::EscapeAssertion("g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act");
}

void RemoveCommentTest()
{
	string s = "asdagnqi _asd  s#asdq asd ";
	cout << Util::RemoveComments(s);
}
