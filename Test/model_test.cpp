#include "pch.h"
#include "../casbin/model/model.h"
#include <fstream>

map<string, string> data = {
	{"request_definition::r","sub, obj, act"},
	{"policy_definition::p" , "sub, obj, act"},
	{"policy_effect::e" , "some(where (p.eft == allow))"},
	{"matchers::m" , "r.sub == p.sub && r.obj == p.obj && r.act == p.act"} 
};

TEST(ModelTest, NewModel) {
	Model* m = new Model();
	EXPECT_EQ(m != NULL, true);
	delete m;
}

TEST(ModelTest, LoadModelFromFile) {
	unique_ptr<Model> m = unique_ptr<Model>(Model::NewModelFromFile("../casbin/examples/RBAC.conf"));
	EXPECT_EQ(m.get() != NULL, true);
}

TEST(ModelTest, LoadModelFromString) {

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
	EXPECT_EQ(m.get() != NULL, true);

}

TEST(ModelTest, LoadModelFromConfig) {
	Model* m = new Model();
	Config c = Config::NewConfigFromFile("../casbin/examples/basic_model.conf");
	m->LoadModelFromConfig(&c);
	EXPECT_EQ(m != NULL, true);
	delete m;

}

TEST(ModelTest, HasSection) {
	Model* m = new Model();
	Config c = Config::NewConfigFromFile("../casbin/examples/basic_model.conf");
	m->LoadModelFromConfig(&c);
	for (auto sec : requiredSections) {
		EXPECT_EQ(m->HasSection(sec), true);
	}
	delete m;
}

TEST(ModelTest, Add_Def) {
	Model* m = new Model();
	string s = "r";
	string v = "sub, obj, act";
	bool ok = m->AddDef(s, s, v);
	EXPECT_EQ(ok, true);
	ok = m->AddDef(s, s, "");
	EXPECT_EQ(ok, false);
	delete m;
}