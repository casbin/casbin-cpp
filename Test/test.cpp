#include "pch.h"
#include "../casbin/enforcer.h"
#include "../casbin/rbac/default-role-manager/default_role_manager.h"
#include "../casbin/util/builtin_operators.h"
#include "../casbin/util/util.h"
#include "../casbin//enforcer_cached.h"




TEST(EnforcerTest, MoreParameters) {
	Enforcer e = Enforcer("../../casbin/examples/MoreParam.conf", "../../casbin/examples/MoreParam.csv");

	EXPECT_EQ(e.enforce("", { "bob","data1","write","school" }), true);
	EXPECT_EQ(e.enforce("", { "bob","data1","write" ,"home" }), false);
	EXPECT_EQ(e.enforce("", { "bob","data2","write","home" }), true);
	EXPECT_EQ(e.enforce("", { "bob","data2","write","school" }), false);
	EXPECT_EQ(e.enforce("", { "alice","data1","write","school" }), false);
	EXPECT_EQ(e.enforce("", { "alice","data1","write","home" }), true);
	EXPECT_EQ(e.enforce("", { "alice","data2","write","school" }), false);
	EXPECT_EQ(e.enforce("", { "alice","data2","write","home" }), false);

	system("pause");
}


TEST(RoleManagerTest, AddTest) {
	RoleManager* rm = new DefaultRoleManager(5);
	rm->Addlink("alice", "admin1", {});
	rm->Addlink("bob", "admin2", {});
	EXPECT_EQ(rm->HasLink( "alice", "admin1", {}) , true);
	EXPECT_EQ(rm->HasLink("alice", "admin2", {}) , false);
	EXPECT_EQ(rm->HasLink("bob", "admin2", {}), true);
	rm->Clear();
	string k;
	delete rm;
	system("pause");
}

TEST(ModelTest, LoadFromTextTest) {

	string text = "[request_definition]\n"
		"r = sub, obj, act\n\n"
		"[policy_definition]\n"
		"p = sub, obj, act\n\n"
		"[role_definition]\n"
		"g = _, _\n\n"
		"[policy_effect]\n"
		"e = some(where (p.eft == allow))\n\n"
		"[matchers]\n"
		"m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";

	unique_ptr<Model> m = unique_ptr<Model>(Model::NewModelFromString(text));

	m->PrintModel();

	unique_ptr<Adapter> adapter = unique_ptr<Adapter>(FileAdapter::newFileAdapter("../../casbin/examples/RBAC.csv"));
	Enforcer e = Enforcer(m, adapter);

	EXPECT_EQ(e.enforce( "", { "bob","data1","write" }), false);
	EXPECT_EQ(e.enforce( "", { "bob","data1","read" }), false);
	EXPECT_EQ(e.enforce( "", { "bob","data2","write" }), true);
	EXPECT_EQ(e.enforce( "", { "bob","data2","read" }), false);
	EXPECT_EQ(e.enforce( "", { "alice","data1","write" }), false);
	EXPECT_EQ(e.enforce( "", { "alice","data1","read" }), true);
	EXPECT_EQ(e.enforce( "", { "alice","data2","write" }), true);
	EXPECT_EQ(e.enforce( "", { "alice","data2","read" }), true);

	system("pause");
}

TEST(ConfigTest, LoadFromFileTest) {

	unique_ptr<Model> m = unique_ptr<Model>(Model::NewModelFromFile( "../../casbin/examples/RBAC.conf"));

	m->PrintModel();

	unique_ptr<Adapter> adapter = unique_ptr<Adapter>(FileAdapter::newFileAdapter("../../casbin/examples/RBAC.csv"));
	Enforcer e = Enforcer(m, adapter);

	EXPECT_EQ(e.enforce( "", { "bob","data1","write" }), false);
	EXPECT_EQ(e.enforce( "", { "bob","data1","read" }), false);
	EXPECT_EQ(e.enforce( "", { "bob","data2","write" }), true);
	EXPECT_EQ(e.enforce( "", { "bob","data2","read" }), false);
	EXPECT_EQ(e.enforce( "", { "alice","data1","write" }), false);
	EXPECT_EQ(e.enforce( "", { "alice","data1","read" }), true);
	EXPECT_EQ(e.enforce( "", { "alice","data2","write" }), true);
	EXPECT_EQ(e.enforce( "", { "alice","data2","read" }), true);

	system("pause");
}

TEST(FilterTest, LoadTest) {

	unique_ptr<Adapter> fa = unique_ptr<Adapter>(Filteredadapter::NewFilteredAdapter("../../casbin/examples/RBAC.csv"));
	unique_ptr<Model> m = unique_ptr<Model>(Model::NewModelFromFile( "../../casbin/examples/RBAC.conf"));
	Enforcer e = Enforcer(m, fa);

	EXPECT_EQ(e.model->HasPolicy("p", "p", { "data2_admin","data2","write" }), true);
	EXPECT_EQ(e.model->HasPolicy("p", "p", { "alice","data1","read" }), true);
	EXPECT_EQ(e.model->HasPolicy("p", "p", { "bob","data2","write" }), true);
	EXPECT_EQ(e.model->HasPolicy("g", "g", { "alice","data2_admin" }), true);

	vector<string> P = { "alice" };
	vector<string> G = { "alice" };
	Filter* filter = new Filter(P, G);
	e.LoadFilteredPolicy(filter);

	EXPECT_EQ(e.model->HasPolicy("p", "p", { "data2_admin","data2","write" }), false);
	EXPECT_EQ(e.model->HasPolicy("p", "p", { "alice","data1","read" }), true);
	EXPECT_EQ(e.model->HasPolicy("p", "p", { "bob","data2","write" }), false);
	EXPECT_EQ(e.model->HasPolicy("g", "g", { "alice","data2_admin" }), true);
	e.model->PrintModel();
	delete filter;
	system("pause");
}

TEST(KeyMatchTest, RawKeyMatchTest) {

	//cout << "Test Key" << endl;
	
	EXPECT_EQ(BuiltinOperators::KeyMatch("/foo/bar","/foo/*"), true);
	EXPECT_EQ(BuiltinOperators::KeyMatch("/fao/bar", "/foo/*"), false);

	EXPECT_EQ(BuiltinOperators::KeyMatch2("/foo/bar", "/foo/*"), true);

	
	EXPECT_EQ(BuiltinOperators::KeyMatch2("/fao/bar", "/foo/*"), false);

	
	EXPECT_EQ(BuiltinOperators::KeyMatch2("/resource1", "/:resource"), true);
	
	EXPECT_EQ(BuiltinOperators::KeyMatch3("/foo/bar", "/foo/*"), true);
	EXPECT_EQ(BuiltinOperators::KeyMatch3("/fao/bar", "/foo/*"), false);
	EXPECT_EQ(BuiltinOperators::KeyMatch3("/resource1", "/{resource}"), true);
	EXPECT_EQ(BuiltinOperators::KeyMatch3("/parent/123/child/456", "/parent/{id}/child/{id}"), true);
	
	EXPECT_EQ(BuiltinOperators::KeyMatch4("/foo/bar", "/foo/*"), true);
	EXPECT_EQ(BuiltinOperators::KeyMatch4("/fao/bar", "/foo/*"), false);
	EXPECT_EQ(BuiltinOperators::KeyMatch4("/parent/123/child/123", "/parent/{id}/child/{id}"), true);
	EXPECT_EQ(BuiltinOperators::KeyMatch4("/parent/123/child/456", "/parent/{id}/child/{id}"), false);

	EXPECT_EQ(BuiltinOperators::IPMatch("192.168.2.123", "192.168.2.0/24"), true);
	EXPECT_EQ(BuiltinOperators::IPMatch("192.168.1.255", "192.168.2.0/24"), false);
	EXPECT_EQ(BuiltinOperators::IPMatch("255.255.255.255", "255.255.0.0/16"), true);
	
	system("pause");
}

TEST(KeyMatchTest, KeyMatch1AndRegexTest) {
	string text = "[request_definition]\n"
		"r = sub, obj, act\n\n"
		"[policy_definition]\n"
		"p = sub, obj, act\n\n"
		"[policy_effect]\n"
		"e = some(where (p.eft == allow))\n\n"
		"[matchers]\n"
		"m = r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)";

	unique_ptr<Model> m = unique_ptr<Model>(Model::NewModelFromString(text));

	m->PrintModel();

	unique_ptr<Adapter> adapter = unique_ptr<Adapter>(FileAdapter::newFileAdapter("../../casbin/examples/keymatch_policy.csv"));
	Enforcer e = Enforcer(m, adapter);

	EXPECT_EQ(e.enforce("", { "alice","/alice_data/anyone","GET" }), true);
	EXPECT_EQ(e.enforce("", { "alice","/alice_data/anyone","POST" }), false);
	EXPECT_EQ(e.enforce("", { "alice","/alice_data/resource1","POST" }), true);
	EXPECT_EQ(e.enforce("", { "cathy","/cathy_data","POST" }), true);
	EXPECT_EQ(e.enforce("", { "cathy","/cathy_data","GET" }), true);
	EXPECT_EQ(e.enforce("", { "cathy","/alice_data/resource1","POST" }), false);
	EXPECT_EQ(e.enforce("", { "bob","/bob_data/any","POST" }), true);
	EXPECT_EQ(e.enforce("", { "bob","/bob_data/any","GET" }), false);
    EXPECT_EQ(e.enforce("", { "bob","/alice_data/resource2","GET" }), true);
	EXPECT_EQ(e.enforce("", { "bob","/alice_data/resource1","GET" }), false);
	system("pause");
}

TEST(KeyMatchTest, KeyMatch2Test) {
	string text = "[request_definition]\n"
		"r = sub, obj, act\n\n"
		"[policy_definition]\n"
		"p = sub, obj, act\n\n"
		"[policy_effect]\n"
		"e = some(where (p.eft == allow))\n\n"
		"[matchers]\n"
		"m = r.sub == p.sub && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)";

	unique_ptr<Model> m = unique_ptr<Model>(Model::NewModelFromString(text));

	m->PrintModel();

	unique_ptr<Adapter> adapter = unique_ptr<Adapter>(FileAdapter::newFileAdapter("../../casbin/examples/keymatch2_policy.csv"));
	Enforcer e = Enforcer(m, adapter);

	EXPECT_EQ(e.enforce("", { "alice","/alice_data/anyone","GET" }), true);
	EXPECT_EQ(e.enforce("", { "alice","/alice_data2/anyone/using/anyone","GET" }), true);
	EXPECT_EQ(e.enforce("", { "alice","/alice_data2/anyone/using/anyone/anyone","GET" }), false);
	system("pause");
}


TEST(Cached, CachedTest) {

	CachedEnforcer e = CachedEnforcer("../../casbin/examples/MoreParam.conf", "../../casbin/examples/MoreParam.csv");

	cout << "Build!" << endl;
	e.model->PrintModel();
	e.EnableCache(true);
	//e.model->PrintModel();
	//e.model->PrintModel();

	
	EXPECT_EQ(e.Enforce({ "bob","data1","write","school" }), true);

	
	EXPECT_EQ(e.Enforce({ "bob","data1","write" ,"home" }), false);
	EXPECT_EQ(e.Enforce({ "bob","data2","write","home" }), true);
	EXPECT_EQ(e.Enforce({ "bob","data2","write","school" }), false);
	EXPECT_EQ(e.Enforce({ "alice","data1","write","school" }), false);
	EXPECT_EQ(e.Enforce({ "alice","data1","write","home" }), true);
	EXPECT_EQ(e.Enforce({ "alice","data2","write","school" }), false);
	EXPECT_EQ(e.Enforce({ "alice","data2","write","home" }), false);

	EXPECT_EQ(e.Enforce({ "bob","data1","write","school" }), true);
	EXPECT_EQ(e.Enforce({ "bob","data1","write" ,"home" }), false);
	EXPECT_EQ(e.Enforce({ "bob","data2","write","home" }), true);
	EXPECT_EQ(e.Enforce({ "bob","data2","write","school" }), false);
	EXPECT_EQ(e.Enforce({ "alice","data1","write","school" }), false);
	EXPECT_EQ(e.Enforce({ "alice","data1","write","home" }), true);
	EXPECT_EQ(e.Enforce({ "alice","data2","write","school" }), false);
	EXPECT_EQ(e.Enforce({ "alice","data2","write","home" }), false);

	cout << "END" << endl;
	system("pause");
}


TEST(LastTest,LastTest2) {
	cout << "LastTest" << endl;
	system("pause");
}

TEST(EnforcerTest, ABACTest1) {

	class TestClass :public MetaClass {
	public:
		int a;
		string s;

		TestClass(int aa, string ss) {
			a = aa;
			s = ss;
		};

		REGISTER_START
			REGISTER_MEMBER(a)
			REGISTER_MEMBER(s)
			REGISTER_END
	};

	string text = "[request_definition]\n"
		"r = sub, obj, act\n\n"
		"[policy_definition]\n"
		"p = sub, obj, act\n\n"
		"[policy_effect]\n"
		"e = some(where (p.eft == allow))\n\n"
		"[matchers]\n"
		"m = r.sub.a == r.obj.a ";

	unique_ptr<Model> m = unique_ptr<Model>(Model::NewModelFromString(text));

	m->PrintModel();

	unique_ptr<Adapter> adapter = unique_ptr<Adapter>(FileAdapter::newFileAdapter("../../casbin/examples/keymatch_policy.csv"));
	Enforcer e = Enforcer(m, adapter);

	TestClass a = TestClass(10, "sss");
	TestClass b = TestClass(20, "bbb");
	TestClass c = TestClass(10, "bbb");
	packToken pc = &c;
	cout << pc.str() << endl;
	EXPECT_EQ(e.enforce({ &a, &b,"write" }), false);
	EXPECT_EQ(e.enforce({ &a, &c,"read" }), true);
	EXPECT_EQ(e.enforce({ &b, &c,"write" }), false);

	system("pause");
}

TEST(EnforcerTest, ABACTest2) {

	class TestClass :public MetaClass {
	public:
		int a;
		string s;

		TestClass(int aa, string ss) {
			a = aa;
			s = ss;
		};

		REGISTER_START
			REGISTER_MEMBER(a)
			REGISTER_MEMBER(s)
			REGISTER_END
	};

	string text = "[request_definition]\n"
		"r = sub, obj, act\n\n"
		"[policy_definition]\n"
		"p = sub, obj, act\n\n"
		"[policy_effect]\n"
		"e = some(where (p.eft == allow))\n\n"
		"[matchers]\n"
		"m = r.sub.s == r.obj.s ";

	unique_ptr<Model> m = unique_ptr<Model>(Model::NewModelFromString(text));

	m->PrintModel();

	unique_ptr<Adapter> adapter = unique_ptr<Adapter>(FileAdapter::newFileAdapter("../../casbin/examples/keymatch_policy.csv"));
	Enforcer e = Enforcer(m, adapter);

	TestClass a = TestClass(10, "sss");
	TestClass b = TestClass(20, "bbb");
	TestClass c = TestClass(10, "bbb");
	packToken pc = &c;
	cout << pc.str() << endl;
	EXPECT_EQ(e.enforce({ &a, &b,"write" }), false);
	EXPECT_EQ(e.enforce({ &a, &c,"read" }), false);
	EXPECT_EQ(e.enforce({ &b, &c,"write" }), true);

	system("pause");
}