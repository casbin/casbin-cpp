/*
#include "util.h"
#include "model.h"
#include "file-adapter.h"
#include "enforcer.h"
#include"Cparse/shunting-yard.h"
#include "role_manager.h"
#include "default_role_manager.h"
#include "log_util.h"
#include "adapter_filtered.h"
#include<algorithm>
#include <regex>

#include <iostream>
using namespace std;
void SplitTest();
void ArrayToStringTest();
void EscapeAssertionTest();
void RemoveCommentTest();
void DemoTest();
void LogTest();
void DemoTest1();
void DemoTest2();
void RBACTest();
void ConfigTest();
void AddRemoveTest();
void FilterTest();

int main()
{
	FilterTest();
	return 0;
}


void DemoTest()
{
	Model*m =new Model();
	m->AddDef("r", "r", "sub, obj, act");
	m->AddDef("p", "p", "sub, obj, act");
	m->AddDef("e", "e", "some(where (p.eft == allow))");
	m->AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act");

	Adapter* adapter = new FileAdapter("-------file------path-------");

	Enforcer e = Enforcer(m, adapter);

	vector<string> s = { "alice","data1","read" };
	vector<string> s1 = { "bob","data2","write" };

	e.model->AddPolicy("p", "p", s);
	e.model->AddPolicy("p", "p", s1);
	e.model->PrintPolicy();
	Error err;
	cout << e.enforce(err,"", { "bob","data2","write" }) <<endl;
	cout << e.enforce(err,"", { "bob","data1","write" }) << endl;
	delete adapter;
}

void DemoTest1()
{
	Model* m =new Model();
	m->AddDef("r", "r", "sub, obj, act");
	m->AddDef("p", "p", "sub, obj, act");
	m->AddDef("e", "e", "some(where (p.eft == allow))");
	m->AddDef("m", "m", "r.sub == p.sub && r.obj == p.obj && r.act == p.act");

	Adapter* adapter = FileAdapter::newFileAdapter("-------file------path-------");

	Enforcer e = Enforcer(m, adapter);

	vector<string> s = { "alice","data1","read" };
	vector<string> s1 = { "bob","data2","write" };
	vector<string> s2 = { "alice","admin1" };

	e.model->AddPolicy("p", "p", s);
	e.model->AddPolicy("p", "p", s1);
	e.model->PrintPolicy();
	Error err;
	cout << e.enforce(err, "", { "bob","data2","write" }) << endl;
	cout << e.enforce(err, "", { "bob","data1","write" }) << endl;
	delete adapter;
}


void DemoTest2() {
	Model* m = new Model();
	m->AddDef("r", "r", "sub, obj, act");
	m->AddDef("p", "p", "sub, obj, act");
	m->AddDef("g", "g", "_, _");
	m->AddDef("e", "e", "some(where (p.eft == allow))");
	m->AddDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act");

	Adapter* adapter = FileAdapter::newFileAdapter("-------file------path-------");

	vector<string> s1 = { "alice","data1","read" };
	vector<string> s2 = { "bob","data2","write" };
	vector<string> s3 = { "data2_admin","data2","read" };
	vector<string> s4 = { "data1_admin","data1","write" };
	vector<string> g1 = { "alice","data2_admin" };
	vector<string> g2 = { "bob","data1_admin" };

	m->AddPolicy("p", "p", s1);
	m->AddPolicy("p", "p", s2);
	m->AddPolicy("p", "p", s3);
	m->AddPolicy("p", "p", s4);
	m->AddPolicy("g","g",g1);
	m->AddPolicy("g", "g", g2);

	Enforcer e = Enforcer(m, adapter);
	e.model->PrintPolicy();

	Error err;
	cout << e.enforce(err, "", { "bob","data2","write" }) << endl;
	cout << e.enforce(err, "", { "bob","data1","write" }) << endl;
	cout << e.enforce(err, "", { "alice","data1","write" }) << endl;
	cout << e.enforce(err, "", { "alice","data2","read" }) << endl;
	cout << e.enforce(err, "", { "alice","data2","write" }) << endl;
	cout << e.enforce(err, "", { "alice","data1","read" }) << endl;
	delete adapter;

}

void AddRemoveTest() {
	Error err;
	Model* m = Model::NewModelFromFile(err, "G:\\GSoC\\RBAC.conf");

	Adapter* adapter = FileAdapter::newFileAdapter("G:\\GSoC\\policy.csv");
	Enforcer e = Enforcer(m, adapter);
	vector<string> s = { "alice","data3","read" };
	vector<string> s1 = { "bob","data3","read" };
	vector<vector<string>> ss = { s,s1 };
	e.model->AddPolicies("p", "p", ss);

	e.model->PrintModel();

	e.model->RemovePolicy("p", "p", s);

	e.model->PrintModel();
}

void FilterTest() {
	Error err;

	Filteredadapter* fa = Filteredadapter::NewFilteredAdapter("G:\\GSoC\\policy.csv");

	Model* m = Model::NewModelFromFile(err, "G:\\GSoC\\RBAC.conf");

	Enforcer e = Enforcer(m, fa);
	vector<string> P = {"alice"};
	vector<string> G = {"alice"};
	Filter* filter = new Filter(P,G);
	e.LoadFilteredPolicy(filter);
	e.model->PrintPolicy();
	delete m;
	delete fa;
	delete filter;
}

void RBACTest() {
	
	RoleManager* rm = new DefaultRoleManager(5);
	rm->Addlink("alice", "admin1", {});
	rm->Addlink("bob", "admin2", {});
	bool res;
	rm->HasLink(res, "alice", "admin1", {});
	cout << res << endl;
	rm->HasLink(res, "alice", "admin2", {});
	cout << res << endl;
	rm->Clear();
}

void ConfigTest() {
	Error err;
	Model* m = Model::NewModelFromFile(err, "G:\\GSoC\\RBAC.conf");

	Adapter* adapter = FileAdapter::newFileAdapter("G:\\GSoC\\policy.csv");
	Enforcer e = Enforcer(m, adapter);
	e.model->PrintModel();
	cout << e.enforce(err, "", { "bob","data2","write" }) << endl;
	cout << e.enforce(err, "", { "bob","data1","write" }) << endl;
	cout << e.enforce(err, "", { "alice","data1","write" }) << endl;
	cout << e.enforce(err, "", { "alice","data2","read" }) << endl;
	cout << e.enforce(err, "", { "alice","data2","write" }) << endl;
	cout << e.enforce(err, "", { "alice","data1","read" }) << endl;
	delete m;
	delete adapter;
}

void LogTest()
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
*/