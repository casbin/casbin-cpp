#include "pch.h"
#include "../casbin/enforcer.h"
#include "../casbin/rbac/default-role-manager/default_role_manager.h"
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


TEST(EnforcerTest, TestBasicModel) {
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

TEST(EnforcerTest, TestBasicModelWithoutSpaces) {
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

//root no policy

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

TEST(EnforcerTest, TestRBACModelWithResourceRoles) {
	Enforcer e = Enforcer("../casbin/examples/rbac_with_resource_roles_model.conf", "../casbin/examples/rbac_with_resource_roles_policy.csv");

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", true);
	testEnforce(t, e, "alice", "data2", "read", false);
	testEnforce(t, e, "alice", "data2", "write", true);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", false);
	testEnforce(t, e, "bob", "data2", "write", true);
}



TEST(EnforcerTest, TestRBACModelWithDomains) {
	//Config cfg = Config::NewConfigFromFile("../casbin/examples/rbac_with_domains_model.conf");
	//cfg.Show();
	Enforcer e = Enforcer("../casbin/examples/rbac_with_domains_model.conf", "../casbin/examples/rbac_with_domains_policy.csv");
	e.model->PrintModel();
	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", true);
	testDomainEnforce(t, e, "alice", "domain1", "data1", "write", true);
	testDomainEnforce(t, e, "alice", "domain1", "data2", "read", false);
	testDomainEnforce(t, e, "alice", "domain1", "data2", "write", false);
	testDomainEnforce(t, e, "bob", "domain2", "data1", "read", false);
	testDomainEnforce(t, e, "bob", "domain2", "data1", "write", false);
	testDomainEnforce(t, e, "bob", "domain2", "data2", "read", true);
	testDomainEnforce(t, e, "bob", "domain2", "data2", "write", true);
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

TEST(EnforcerTest, TestRBACModelWithPattern) {
	Enforcer e = Enforcer("../casbin/examples/rbac_with_pattern_model.conf", "../casbin/examples/rbac_with_pattern_policy.csv");

	// Here's a little confusing: the matching function here is not the custom function used in matcher.
	// It is the matching function used by "g" (and "g2", "g3" if any..)
	// You can see in policy that: "g2, /book/:id, book_group", so in "g2()" function in the matcher, instead
	// of checking whether "/book/:id" equals the obj: "/book/1", it checks whether the pattern matches.
	// You can see it as normal RBAC: "/book/:id" == "/book/1" becomes KeyMatch2("/book/:id", "/book/1")
	e.rm->AddMatchingFunc("KeyMatch2", BuiltinOperators::KeyMatch2);
	testEnforce(t, e, "alice", "/book/1", "GET", true);
	testEnforce(t, e, "alice", "/book/2", "GET", true);
	testEnforce(t, e, "alice", "/pen/1", "GET", true);
	testEnforce(t, e, "alice", "/pen/2", "GET", false);
	testEnforce(t, e, "bob", "/book/1", "GET", false);
	testEnforce(t, e, "bob", "/book/2", "GET", false);
	testEnforce(t, e, "bob", "/pen/1", "GET", true);
	testEnforce(t, e, "bob", "/pen/2", "GET", true);

	// AddMatchingFunc() is actually setting a function because only one function is allowed,
	// so when we set "KeyMatch3", we are actually replacing "KeyMatch2" with "KeyMatch3".
	e.rm->AddMatchingFunc("KeyMatch3", BuiltinOperators::KeyMatch3);
	testEnforce(t, e, "alice", "/book2/1", "GET", true);
	testEnforce(t, e, "alice", "/book2/2", "GET", true);
	testEnforce(t, e, "alice", "/pen2/1", "GET", true);
	testEnforce(t, e, "alice", "/pen2/2", "GET", false);
	testEnforce(t, e, "bob", "/book2/1", "GET", false);
	testEnforce(t, e, "bob", "/book2/2", "GET", false);
	testEnforce(t, e, "bob", "/pen2/1", "GET", true);
	testEnforce(t, e, "bob", "/pen2/2", "GET", true);
}




TEST(EnforcerTest, TestRBACModelWithCustomRoleManager) {
	Enforcer e = Enforcer("../casbin/examples/rbac_model.conf", "../casbin/examples/rbac_policy.csv");
	e.SetRoleManager(unique_ptr<RoleManager>(new DefaultRoleManager(10)));
	e.LoadModel();
	e.LoadPolicy();

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", true);
	testEnforce(t, e, "alice", "data2", "write", true);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", false);
	testEnforce(t, e, "bob", "data2", "write", true);
}

TEST(EnforcerTest, TestKeyMatchModel) {
	Enforcer e = Enforcer("../casbin/examples/keymatch_model.conf", "../casbin/examples/keymatch_policy.csv");

	testEnforce(t, e, "alice", "/alice_data/resource1", "GET", true);
	testEnforce(t, e, "alice", "/alice_data/resource1", "POST", true);
	testEnforce(t, e, "alice", "/alice_data/resource2", "GET", true);
	testEnforce(t, e, "alice", "/alice_data/resource2", "POST", false);
	testEnforce(t, e, "alice", "/bob_data/resource1", "GET", false);
	testEnforce(t, e, "alice", "/bob_data/resource1", "POST", false);
	testEnforce(t, e, "alice", "/bob_data/resource2", "GET", false);
	testEnforce(t, e, "alice", "/bob_data/resource2", "POST", false);
	testEnforce(t, e, "bob", "/alice_data/resource1", "GET", false);
	testEnforce(t, e, "bob", "/alice_data/resource1", "POST", false);
	testEnforce(t, e, "bob", "/alice_data/resource2", "GET", true);
	testEnforce(t, e, "bob", "/alice_data/resource2", "POST", false);
	testEnforce(t, e, "bob", "/bob_data/resource1", "GET", false);
	testEnforce(t, e, "bob", "/bob_data/resource1", "POST", true);
	testEnforce(t, e, "bob", "/bob_data/resource2", "GET", false);
	testEnforce(t, e, "bob", "/bob_data/resource2", "POST", true);

	testEnforce(t, e, "cathy", "/cathy_data", "GET", true);
	testEnforce(t, e, "cathy", "/cathy_data", "POST", true);
	testEnforce(t, e, "cathy", "/cathy_data", "DELETE", false);
}

TEST(EnforcerTest, TestKeyMatch2Model) {
	Enforcer e = Enforcer("../casbin/examples/keymatch2_model.conf", "../casbin/examples/keymatch2_policy.csv");

	testEnforce(t, e, "alice", "/alice_data", "GET", false);
	testEnforce(t, e, "alice", "/alice_data/resource1", "GET", true);
	testEnforce(t, e, "alice", "/alice_data2/myid", "GET", false);
	testEnforce(t, e, "alice", "/alice_data2/myid/using/res_id", "GET", true);
}

bool CustomFunction(string key1,  string key2){
	if (key1 == "/alice_data2/myid/using/res_id" && key2 == "/alice_data/:resource") {
		return true;
	}
	else if (key1 == "/alice_data2/myid/using/res_id" && key2 == "/alice_data2/:id/using/:resId") {
		return true;
	}
	else {
		return false;
	}
}


packToken CustomFunctionWrapper(TokenMap GlobalMap, TokenMap Scope) {
	return CustomFunction(Scope["A"].asString(), Scope["B"].asString());
}

TEST(EnforcerTest, TestKeyMatchCustomModel) {
	Enforcer e = Enforcer("../casbin/examples/keymatch_custom_model.conf", "../casbin/examples/keymatch2_policy.csv");
	e.AddFunction("keyMatchCustom", &CustomFunctionWrapper);
	testEnforce(t, e, "alice", "/alice_data2/myid", "GET", false);
	testEnforce(t, e, "alice", "/alice_data2/myid/using/res_id", "GET", true);
}



TEST(EnforcerTest, TestIPMatchModel) {
	Enforcer e = Enforcer("../casbin/examples/ipmatch_model.conf", "../casbin/examples/ipmatch_policy.csv");

	testEnforce(t, e, "192.168.2.123", "data1", "read", true);
	testEnforce(t, e, "192.168.2.123", "data1", "write", false);
	testEnforce(t, e, "192.168.2.123", "data2", "read", false);
	testEnforce(t, e, "192.168.2.123", "data2", "write", false);

	testEnforce(t, e, "192.168.0.123", "data1", "read", false);
	testEnforce(t, e, "192.168.0.123", "data1", "write", false);
	testEnforce(t, e, "192.168.0.123", "data2", "read", false);
	testEnforce(t, e, "192.168.0.123", "data2", "write", false);

	testEnforce(t, e, "10.0.0.5", "data1", "read", false);
	testEnforce(t, e, "10.0.0.5", "data1", "write", false);
	testEnforce(t, e, "10.0.0.5", "data2", "read", false);
	testEnforce(t, e, "10.0.0.5", "data2", "write", true);

	testEnforce(t, e, "192.168.0.1", "data1", "read", false);
	testEnforce(t, e, "192.168.0.1", "data1", "write", false);
	testEnforce(t, e, "192.168.0.1", "data2", "read", false);
	testEnforce(t, e, "192.168.0.1", "data2", "write", false);
}

//To use ABAC model,you should registe the member of the class,and inherit the MetaClass
class testResource : public MetaClass {
public:
	string Name;
	string Owner;
	REGISTER_START
		REGISTER_MEMBER(Name)
		REGISTER_MEMBER(Owner)
		REGISTER_END
};

testResource newTestResource(string name, string owner)  {
	testResource r = testResource();
	r.Name = name;
	r.Owner = owner;
	return r;
}

void testEnforce(int t, Enforcer& e, string a, testResource* b, string c, bool res) {
	//to use ABAC model,you should pass by pointer
	bool myres = e.EnforceABAC({ a,b,c });
	EXPECT_EQ(myres, res);
}

TEST(EnforcerTest, TestABACModel) {
	Enforcer e = Enforcer("../casbin/examples/abac_model.conf");

	testResource data1 = newTestResource("data1", "alice");
	testResource data2 = newTestResource("data2", "bob");

	testEnforce(t, e, "alice", &data1, "read", true);
	testEnforce(t, e, "alice", &data1, "write", true);
	testEnforce(t, e, "alice", &data2, "read", false);
	testEnforce(t, e, "alice", &data2, "write", false);
	testEnforce(t, e, "bob", &data1, "read", false);
	testEnforce(t, e, "bob", &data1, "write", false);
	testEnforce(t, e, "bob", &data2, "read", true);
	testEnforce(t, e, "bob", &data2, "write", true);
}

TEST(EnforcerTest, TestRBACModelInMultiLines) {
	Enforcer e = Enforcer("../casbin/examples/rbac_model_in_multi_line.conf", "../casbin/examples/rbac_policy.csv");

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", true);
	testEnforce(t, e, "alice", "data2", "write", true);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", false);
	testEnforce(t, e, "bob", "data2", "write", true);
}

TEST(EnforcerTest, TestPriorityModel) {
	Enforcer e = Enforcer("../casbin/examples/priority_model.conf", "../casbin/examples/priority_policy.csv");

	testEnforce(t, e, "alice", "data1", "read", true);
	testEnforce(t, e, "alice", "data1", "write", false);
	testEnforce(t, e, "alice", "data2", "read", false);
	testEnforce(t, e, "alice", "data2", "write", false);
	testEnforce(t, e, "bob", "data1", "read", false);
	testEnforce(t, e, "bob", "data1", "write", false);
	testEnforce(t, e, "bob", "data2", "read", true);
	testEnforce(t, e, "bob", "data2", "write", false);
}

TEST(EnforcerTest, TestPriorityModelIndeterminate) {
	Enforcer e = Enforcer("../casbin/examples/priority_model.conf", "../casbin/examples/priority_indeterminate_policy.csv");
	testEnforce(t, e, "alice", "data1", "read", false);
}