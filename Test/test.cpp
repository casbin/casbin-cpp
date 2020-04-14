#include "pch.h"
#include "../casbin/enforcer.h"
#include "../casbin/rbac/default-role-manager/default_role_manager.h"

TEST(EnforcerTest, PassByReferenceTest) {
	FileAdapter fa = FileAdapter("../../casbin/examples/MoreParam.csv");
	Model m = Model::ModelFromFile("../../casbin/examples/MoreParam.conf");

	
	Enforcer e = Enforcer(m,fa);
	/*

	EXPECT_EQ(e.enforce("", { "bob","data1","write","school" }), true);
	EXPECT_EQ(e.enforce("", { "bob","data1","write" ,"home" }), false);
	EXPECT_EQ(e.enforce("", { "bob","data2","write","home" }), true);
	EXPECT_EQ(e.enforce("", { "bob","data2","write","school" }), false);
	EXPECT_EQ(e.enforce("", { "alice","data1","write","school" }), false);
	EXPECT_EQ(e.enforce("", { "alice","data1","write","home" }), true);
	EXPECT_EQ(e.enforce("", { "alice","data2","write","school" }), false);
	EXPECT_EQ(e.enforce("", { "alice","data2","write","home" }), false);
	*/
	system("pause");
}

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

