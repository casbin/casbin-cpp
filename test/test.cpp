#include "pch.h"
#include "../casbin/config/config.h"
#include "../casbin/log/logger.h"
#include "../casbin/enforcer.h"
#include "../casbin/util/matcher.h"

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

TEST(LogTest, WriteFileTest) {
	Logger log;
	log.print("Sample log");
}

TEST(EnforcerTest, PolicyTest) {
	Enforcer e("../../examples/model.conf", "../../examples/policy.csv");
	vector<string> temp = e.getPolicy();
	vector<string> result = { "alice,data1,read", "bob,data2,write" };

	EXPECT_EQ(join(temp, '-'), join(result, '-'));
}

TEST(EnforcerTest, ModelTest) {
	Enforcer e("../../examples/model.conf", "../../examples/policy.csv");
	EXPECT_EQ(true, e.enforce("alice", "data1", "read"));
	EXPECT_EQ(false, e.enforce("alice", "data1", "write"));
	EXPECT_EQ(true, e.enforce("bob", "data2", "write"));
	EXPECT_EQ(false, e.enforce("bob", "data2", "read"));
}

bool g(string a, string b) {
	return true;
}

TEST(MatcherTest, ParsingTest) {
	map<string, function<bool(string, string)>> functions;
	map<string, string> structure = { { "r.sub", "alice" }, { "p.sub", "alice" } };
	functions.insert({ "g", g });
	Matcher m(functions);

	bool result = m.eval(structure, "g(a, b) && r.sub == p.sub");
	EXPECT_EQ(true, result);
}

TEST(EnforcerTest, RBACTest) {
	Enforcer e("../../examples/rbac_model.conf", "../../examples/rbac_policy.csv");

	EXPECT_EQ(true, e.enforce("alice", "data2", "read"));
	EXPECT_EQ(false, e.enforce("alice", "data1", "write"));
	EXPECT_EQ(true, e.enforce("bob", "data2", "write"));
	EXPECT_EQ(false, e.enforce("bob", "data2", "read"));
}