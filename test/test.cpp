#include "pch.h"
#include "../casbin/config/config.h"
#include "../casbin/log/logger.h"
#include "../casbin/enforcer.h"

TEST(ConfAdapterTest, FileReadTest) {
	Config e("../../examples/model.conf");
	const auto temp = join(e.strings("request_definition::r"), ',');

	EXPECT_EQ("sub, obj, act", e.get("request_definition::r"));
	EXPECT_EQ("sub,obj,act", temp);
	EXPECT_EQ("sub, obj, act", e.get("policy_definition::p"));
	EXPECT_EQ("some(where (p.eft == allow))", e.get("policy_effect::e"));
	EXPECT_EQ("r.sub == p.sub && r.obj == p.obj && r.act == p.act", e.get("matchers::m"));
}

TEST(ConfAdapterTest, StringReadTest) {
	const string text = "[request_definition] ; This is comment\n"
		"r = sub, obj, act\n"
		"[policy_definition]\n"
		"p = sub, obj, act\n"
		"[policy_effect]\n"
		"e = some(where(p.eft == allow))\n"
		"[matchers]\n"
		"m = r.sub == p.sub && r.obj == p.obj && r.act == p.act";

	Config e;
	e.read_from_text(text);
	e.set("test::key", "value");

	EXPECT_EQ("sub, obj, act", e.get("request_definition::r"));
	EXPECT_EQ("sub, obj, act", e.get("policy_definition::p"));
	EXPECT_EQ("some(where(p.eft == allow))", e.get("policy_effect::e"));
	EXPECT_EQ("r.sub == p.sub && r.obj == p.obj && r.act == p.act", e.get("matchers::m"));
	EXPECT_EQ("value", e.get("test::key"));
}

TEST(LogTest, WriteFileTest) {
	const Logger log;
	log.print("Sample log");
}

TEST(EnforcerTest, PolicyTest) {
	Enforcer e("../../examples/model.conf", "../../examples/policy.csv");
	auto temp = e.get_policy();
	const vector<string> result = { "alice,data1,read", "bob,data2,write" };

	EXPECT_EQ(join(temp, '-'), join(result, '-'));
}

TEST(EnforcerTest, ModelTest) {
	Enforcer e("../../examples/model.conf", "../../examples/policy.csv");

	EXPECT_EQ(true, e.enforce(string("alice"), string("data1"), string("read")));
	EXPECT_EQ(false, e.enforce(string("alice"), string("data1"), string("write")));
	EXPECT_EQ(true, e.enforce(string("bob"), string("data2"), string("write")));
	EXPECT_EQ(false, e.enforce(string("bob"), string("data2"), string("read")));
}

TEST(EnforcerTest, RBACTest) {
	Enforcer e("../../examples/rbac_model.conf", "../../examples/rbac_policy.csv");

	EXPECT_EQ(true, e.enforce(string("alice"), string("data2"), string("read")));
	EXPECT_EQ(false, e.enforce(string("alice"), string("data1"), string("write")));
	EXPECT_EQ(true, e.enforce(string("bob"), string("data2"), string("write")));
	EXPECT_EQ(false, e.enforce(string("bob"), string("data2"), string("read")));
}

TEST(EnforcerTest, KeyMatchTest) {
	Enforcer e("../../examples/keymatch_model.conf", "../../examples/keymatch_policy.csv");

	EXPECT_EQ(true, e.enforce(string("alice"), string("/alice_data"), string("GET")));
	EXPECT_EQ(true, e.enforce(string("cathy"), string("/cathy_data"), string("POST")));
	EXPECT_EQ(true, e.enforce(string("cathy"), string("/cathy_data"), string("GET")));
	EXPECT_EQ(false, e.enforce(string("bob"), string("/alice_data/"), string("GET")));
	EXPECT_EQ(true, e.enforce(string("bob"), string("/alice_data/resource2"), string("GET")));
	EXPECT_EQ(true, e.enforce(string("bob"), string("/bob_data/resource1"), string("POST")));
	EXPECT_EQ(false, e.enforce(string("bob"), string("/bob_data/resource1"), string("GET")));
}

TEST(EnforcerTest, KeyMatch2Test) {
	Enforcer e("../../examples/keymatch2_model.conf", "../../examples/keymatch2_policy.csv");

	EXPECT_EQ(true, e.enforce(string("alice"), string("/alice_data/af"), string("GET")));
	EXPECT_EQ(false, e.enforce(string("alice"), string("/alice_data/af"), string("POST")));
	EXPECT_EQ(false, e.enforce(string("bob"), string("/alice_data/af"), string("POST")));
}

TEST(EnforcerTest, IPMatchTest) {
	Enforcer e("../../examples/ipmatch_model.conf", "../../examples/ipmatch_policy.csv");

	EXPECT_EQ(true, e.enforce(string("192.168.2.255"), string("data1"), string("read")));
	EXPECT_EQ(false, e.enforce(string("192.169.2.255"), string("data1"), string("read")));
}

TEST(EnforcerTest, ABACTest) {
	Enforcer e("../../examples/abac_model.conf", "../../examples/policy.csv");

	EXPECT_EQ(true, e.enforce(string("alice"), unordered_map<string, string>({ { "Owner", "alice" } }), string("read")));
	EXPECT_EQ(false, e.enforce(string("bob"), unordered_map<string, string>({ { "Owner", "alice" } }), string("read")));
	EXPECT_EQ(false, e.enforce(unordered_map<string, string>({ { "Owner", "alice" } }), unordered_map<string, string>({ { "Owner", "alice" } }), string("read")));
}