#include "pch.h"
#include "../casbin/enforcer.h"
#include "../casbin/util/builtin_operators.h"

int t = 0;

void testEnforce(int t, Enforcer& e, string a, string b, string c, bool res) {
	bool myres = e.Enforce({a,b,c});
	EXPECT_EQ(myres, res);
}

void testEnforce(int t, Enforcer& e, string a, string b, bool res) {
	bool myres = e.Enforce({ a,b });
	EXPECT_EQ(myres, res);
}

void testEnforceWithoutUsers(int t, Enforcer& e, string a, string b, bool res) {
	bool myres = e.Enforce({ a,b });
	EXPECT_EQ(myres, res);
}

void testDomainEnforce(int t, Enforcer& e, string sub, string domain,string obj,string act, bool res) {
	bool myres = e.Enforce({ sub,domain,obj,act });
	EXPECT_EQ(myres, res);
}


TEST(EnforcerTest,TestBasicModel){
	Enforcer e = Enforcer("../casbin/examples/basic_model.conf", "../casbin/examples/basic_policy.csv");

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", false);
	testEnforce(t, e, "alice", "data2", "write", false);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", false);
	testEnforce(t, e, "bob", "data2", "write", true);
}

TEST(EnforcerTest,TestBasicModelWithoutSpaces) {
	Enforcer e = Enforcer("../casbin/examples/basic_model_without_spaces.conf", "../casbin/examples/basic_policy.csv");

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", false);
	testEnforce(t, e, "alice", "data2", "write", false);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", false);
	testEnforce(t, e, "bob", "data2", "write", true);
}

TEST(EnforcerTest, TestBasicModelNoPolicy) {
	Enforcer e = Enforcer("../casbin/examples/basic_model.conf");

	testEnforce(t, e, "alice", "data1", "read", false);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", false);
	testEnforce(t, e, "alice", "data2", "write", false);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", false);
	testEnforce(t, e, "bob", "data2", "write", false);
}


TEST(EnforcerTest, TestBasicModelWithRoot) {
	Enforcer e = Enforcer("../casbin/examples/basic_with_root_model.conf", "../casbin/examples/basic_policy.csv");

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", false);
	testEnforce(t, e, "alice", "data2", "write", false);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", false);
	testEnforce(t, e, "bob", "data2", "write", true);
	testEnforce(t, e, "root", "data1", "read", true);
	testEnforce(t, e, "root", "data1", "write", true);
	testEnforce(t, e, "root", "data2", "read", true);
	testEnforce(t, e, "root", "data2", "write", true);
}


TEST(EnforcerTest, TestBasicModelWithoutUsers) {
	Enforcer e = Enforcer("../casbin/examples/basic_without_users_model.conf", "../casbin/examples/basic_without_users_policy.csv");

	testEnforceWithoutUsers(t, e, "data1", "read", true);
	testEnforceWithoutUsers(t, e, "data1", "write", false);
	testEnforceWithoutUsers(t, e, "data2", "read", false);
	testEnforceWithoutUsers(t, e, "data2", "write", true);
}

TEST(EnforcerTest, TestBasicModelWithoutResources) {
	Enforcer e = Enforcer("../casbin/examples/basic_without_resources_model.conf", "../casbin/examples/basic_without_resources_policy.csv");

	testEnforceWithoutUsers(t, e, "alice", "read", true);
	testEnforceWithoutUsers(t, e, "alice", "write", false);
	testEnforceWithoutUsers(t, e, "bob", "read", false);
	testEnforceWithoutUsers(t, e, "bob", "write", true);
}

TEST(EnforcerTest, TestRBACModel) {
	Enforcer e = Enforcer("../casbin/examples/rbac_model.conf", "../casbin/examples/rbac_policy.csv");

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", true);
	testEnforce(t, e, "alice", "data2", "write", true);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", false);
	testEnforce(t, e, "bob", "data2", "write", true);
}

TEST(EnforcerTest, TestRBACModelWithDeny) {
	Enforcer e = Enforcer("../casbin/examples/rbac_with_deny_model.conf", "../casbin/examples/rbac_with_deny_policy.csv");

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", true);
	testEnforce(t, e, "alice", "data2", "write", false);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", false);
	testEnforce(t, e, "bob", "data2", "write", true);
}

TEST(EnforcerTest, TestRBACModelWithOnlyDeny) {
	Enforcer e = Enforcer("../casbin/examples/rbac_with_not_deny_model.conf", "../casbin/examples/rbac_with_deny_policy.csv");

	testEnforce(t, e, "alice", "data2", "write", false);
}

TEST(EnforcerTest, TestRBACModelWithCustomData) {
	Enforcer e = Enforcer("../casbin/examples/rbac_model.conf", "../casbin/examples/rbac_policy.csv");

	// You can add custom data to a grouping policy, Casbin will ignore it. It is only meaningful to the caller.
	// This feature can be used to store information like whether "bob" is an end user (so no subject will inherit "bob")
	// For Casbin, it is equivalent to: e.AddGroupingPolicy("bob", "data2_admin")
	e.AddGroupingPolicy({ "bob", "data2_admin", "custom_data" });

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", true);
	testEnforce(t, e, "alice", "data2", "write", true);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", true);
	testEnforce(t, e, "bob", "data2", "write", true);

	// You should also take the custom data as a parameter when deleting a grouping policy.
	// e.RemoveGroupingPolicy("bob", "data2_admin") won't work.
	// Or you can remove it by using RemoveFilteredGroupingPolicy().
	e.RemoveGroupingPolicy({ "bob", "data2_admin", "custom_data" });

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", true);
	testEnforce(t, e, "alice", "data2", "write", true);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", false);
	testEnforce(t, e, "bob", "data2", "write", true);
};
