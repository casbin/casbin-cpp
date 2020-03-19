#include "pch.h"
#include "../casbin/csv_adapter.h"
#include "../casbin/config.h"
#include "../casbin/model.h"
#include "../casbin/logger.h"

TEST(CSVAdapterTest, FileReadTest) {
	CSVAdapter e;
	e.readFile("../../examples/policy.csv");
	vector<vector<string>> data = e.getData();
	EXPECT_EQ(2, data.size()) << "The resulting size is " << data.size();
}

TEST(ConfAdapterTest, FileReadTest) {
	Config e("../../examples/model.conf");
	string temp = join(e.strings("request_definition::r"), ',');

	EXPECT_EQ("sub, obj, act", e.get("request_definition::r"));
	EXPECT_EQ("sub,obj,act", temp);
	EXPECT_EQ("sub, obj, act", e.get("policy_definition::p"));
	EXPECT_EQ("some(where (p.eft == allow))", e.get("policy_effect::e"));
	EXPECT_EQ("r.sub == p.sub && r.obj == p.obj && r.act == p.act", e.get("matchers::m"));
}

TEST(ConfAdapterTest, StringReadTest) {
	string text = "[request_definition] ; This is comment\n"
		"r = sub, obj, act\n"
		"[policy_definition]\n"
		"p = sub, obj, act\n"
		"[policy_effect]\n"
		"e = some(where(p.eft == allow))\n"
		"[matchers]\n"
		"m = r.sub == p.sub && r.obj == p.obj && r.act == p.act";

	Config e;
	e.readFromText(text);
	e.set("test::key", "value");

	EXPECT_EQ("sub, obj, act", e.get("request_definition::r"));
	EXPECT_EQ("sub, obj, act", e.get("policy_definition::p"));
	EXPECT_EQ("some(where(p.eft == allow))", e.get("policy_effect::e"));
	EXPECT_EQ("r.sub == p.sub && r.obj == p.obj && r.act == p.act", e.get("matchers::m"));
	EXPECT_EQ("value", e.get("test::key"));
}

TEST(ModelTest, FileReadTest) {
	//Model m("../../examples/model.conf");
	//EXPECT_EQ("r.sub == p.sub && r.obj == p.obj && r.act == p.act", m.getMatcherString()) << "The matcher string is " << m.getMatcherString();
	// EXPECT_EQ("some(where (p.eft == allow))", m.getPolicyEffect()) << "The policy effect is " << m.getPolicyEffect();
}

TEST(ModelTest, RPTest) {
	//Model m("../../examples/model.conf");
	//map<string, vector<string>> structure = m.getRPStructure();
	// EXPECT_EQ("r.sub,r.obj,r.act", join(structure.find("request_definition")->second, ',')) << "The request string is " << join(structure.find("request_definition")->second, ',');
	// EXPECT_EQ("p.sub,p.obj,p.act", join(structure.find("policy_definition")->second, ',')) << "The request string is " << join(structure.find("policy_definition")->second, ',');
}

TEST(LogTest, WriteFileTest) {
	Logger log;
	log.print("Sample log");
}