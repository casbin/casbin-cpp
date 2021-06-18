/*
* Copyright 2020 The casbin Authors. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* This is a test file for testing built in functions in casbin
*/

#include <gtest/gtest.h>
#include <casbin/casbin.h>

namespace {

casbin::Scope InitializeParams(const std::string& sub, const std::string& obj, const std::string& act){
    casbin::Scope scope = casbin::InitializeScope();
    casbin::PushObject(scope, "r");
    casbin::PushStringPropToObject(scope, "r", sub, "sub");
    casbin::PushStringPropToObject(scope, "r", obj, "obj");
    casbin::PushStringPropToObject(scope, "r", act, "act");

    return scope;
}

casbin::Scope InitializeParamsWithoutUsers(const std::string& obj, const std::string& act) {
    casbin::Scope scope = casbin::InitializeScope();
    casbin::PushObject(scope, "r");
    casbin::PushStringPropToObject(scope, "r", obj, "obj");
    casbin::PushStringPropToObject(scope, "r", act, "act");
    return scope;
}

casbin::Scope InitializeParamsWithoutResources(const std::string& sub, const std::string& act) {
    casbin::Scope scope = casbin::InitializeScope();
    casbin::PushObject(scope, "r");
    casbin::PushStringPropToObject(scope, "r", sub, "sub");
    casbin::PushStringPropToObject(scope, "r", act, "act");

    return scope;
}

casbin::Scope InitializeParamsWithDomains(const std::string& sub, const std::string& domain, const std::string& obj, const std::string& act) {
    casbin::Scope scope = casbin::InitializeScope();
    casbin::PushObject(scope, "r");
    casbin::PushStringPropToObject(scope, "r", sub, "sub");
    casbin::PushStringPropToObject(scope, "r", domain, "dom");
    casbin::PushStringPropToObject(scope, "r", obj, "obj");
    casbin::PushStringPropToObject(scope, "r", act, "act");
    return scope;
}

void TestEnforce(casbin::Enforcer& e, casbin::Scope& scope, bool res) {
    ASSERT_EQ(res, e.Enforce(scope));
}

TEST(TestModelEnforcer, TestBasicModel) {
    std::string model = "../../examples/basic_model.conf";
    std::string policy = "../../examples/basic_policy.csv";
    casbin::Enforcer e(model, policy);

    casbin::Scope scope;

    scope = InitializeParams("alice", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "write");
    TestEnforce(e, scope, true);
}
            
TEST(TestModelEnforcer, TestBasicModelWithoutSpaces) {
    std::string model = "../../examples/basic_model_without_spaces.conf";
    std::string policy = "../../examples/basic_policy.csv";
    casbin::Enforcer e(model, policy);

    casbin::Scope scope = InitializeParams("alice", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestBasicModelNoPolicy) {
    std::string model = "../../examples/basic_model.conf";
    casbin::Enforcer e(model);

    casbin::Scope scope = InitializeParams("alice", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "write");
    TestEnforce(e, scope, false);
}

TEST(TestModelEnforcer, TestBasicModelWithRoot) {
    std::string model = "../../examples/basic_with_root_model.conf";
    std::string policy = "../../examples/basic_policy.csv";
    casbin::Enforcer e(model, policy);

    casbin::Scope scope = InitializeParams("alice", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "write");
    TestEnforce(e, scope, true);
    scope = InitializeParams("root", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("root", "data1", "write");
    TestEnforce(e, scope, true);
    scope = InitializeParams("root", "data2", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("root", "data2", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestBasicModelWithRootNoPolicy) {
    std::string model = "../../examples/basic_with_root_model.conf";
    casbin::Enforcer e(model);

    casbin::Scope scope = InitializeParams("alice", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("root", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("root", "data1", "write");
    TestEnforce(e, scope, true);
    scope = InitializeParams("root", "data2", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("root", "data2", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestBasicModelWithoutUsers) {
    std::string model = "../../examples/basic_without_users_model.conf";
    std::string policy = "../../examples/basic_without_users_policy.csv";
    casbin::Enforcer e(model, policy);

    casbin::Scope scope = InitializeParamsWithoutUsers("data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParamsWithoutUsers("data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithoutUsers("data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithoutUsers("data2", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestBasicModelWithoutResources) {
    std::string model = "../../examples/basic_without_resources_model.conf";
    std::string policy = "../../examples/basic_without_resources_policy.csv";
    casbin::Enforcer e(model, policy);

    casbin::Scope scope = InitializeParamsWithoutResources("alice", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParamsWithoutResources("alice", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithoutResources("bob", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithoutResources("bob", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestRBACModel) {
    std::string model = "../../examples/rbac_model.conf";
    std::string policy = "../../examples/rbac_policy.csv";
    casbin::Enforcer e(model, policy);

    casbin::Scope scope = InitializeParams("alice", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, true);
    scope = InitializeParams("bob", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestRBACModelWithResourceRoles) {
    std::string model = "../../examples/rbac_with_resource_roles_model.conf";
    std::string policy = "../../examples/rbac_with_resource_roles_policy.csv";
    casbin::Enforcer e(model, policy);

    casbin::Scope scope = InitializeParams("alice", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data1", "write");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, true);
    scope = InitializeParams("bob", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestRBACModelWithDomains) {
    std::string model = "../../examples/rbac_with_domains_model.conf";
    std::string policy = "../../examples/rbac_with_domains_policy.csv";
    casbin::Enforcer e(model, policy);
    
    casbin::Scope scope = InitializeParamsWithDomains("alice", "domain1", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParamsWithDomains("alice", "domain1", "data1", "write");
    TestEnforce(e, scope, true);
    scope = InitializeParamsWithDomains("alice", "domain1", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("alice", "domain1", "data2", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data2", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParamsWithDomains("bob", "domain2", "data2", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestRBACModelWithDomainsAtRuntime) {
    std::string model = "../../examples/rbac_with_domains_model.conf";
    casbin::Enforcer e(model);

    std::vector<std::string> params{ "admin", "domain1", "data1", "read" };
    e.AddPolicy(params);
    params = std::vector<std::string>{ "admin", "domain1", "data1", "write" };
    e.AddPolicy(params);
    params = std::vector<std::string>{ "admin", "domain2", "data2", "read" };
    e.AddPolicy(params);
    params = std::vector<std::string>{ "admin", "domain2", "data2", "write" };
    e.AddPolicy(params);

    params = std::vector<std::string>{ "alice", "admin", "domain1" };
    e.AddGroupingPolicy(params);
    params = std::vector<std::string>{ "bob", "admin", "domain2" };
    e.AddGroupingPolicy(params);

    casbin::Scope scope = InitializeParamsWithDomains("alice", "domain1", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParamsWithDomains("alice", "domain1", "data1", "write");
    TestEnforce(e, scope, true);
    scope = InitializeParamsWithDomains("alice", "domain1", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("alice", "domain1", "data2", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data2", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParamsWithDomains("bob", "domain2", "data2", "write");
    TestEnforce(e, scope, true);

    // Remove all policy rules related to domain1 and data1.
    params = std::vector<std::string>{ "domain1", "data1" };
    e.RemoveFilteredPolicy(1, params);

    scope = InitializeParamsWithDomains("alice", "domain1", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("alice", "domain1", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("alice", "domain1", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("alice", "domain1", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data2", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParamsWithDomains("bob", "domain2", "data2", "write");
    TestEnforce(e, scope, true);

    // Remove the specified policy rule.
    params = std::vector<std::string>{ "admin", "domain2", "data2", "read" };
    e.RemovePolicy(params);

    scope = InitializeParamsWithDomains("alice", "domain1", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("alice", "domain1", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("alice", "domain1", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("alice", "domain1", "data2", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParamsWithDomains("bob", "domain2", "data2", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestRBACModelWithDomainsAtRuntimeMockAdapter) {
    std::string model = "../../examples/rbac_with_domains_model.conf";
    std::string policy = "../../examples/rbac_with_domains_policy.csv";
    std::shared_ptr<casbin::Adapter> adapter = std::make_shared<casbin::FileAdapter>(policy);
    casbin::Enforcer e(model, adapter);

    std::vector<std::string> params{ "admin", "domain3", "data1", "read" };
    e.AddPolicy(params);
    params = std::vector<std::string>{ "alice", "admin", "domain3" };
    e.AddGroupingPolicy(params);

    casbin::Scope scope = InitializeParamsWithDomains("alice", "domain3", "data1", "read");
    TestEnforce(e, scope, true);

    scope = InitializeParamsWithDomains("alice", "domain1", "data1", "read");
    TestEnforce(e, scope, true);
    params = std::vector<std::string>{ "domain1", "data1" };
    e.RemoveFilteredPolicy(1, params);
    scope = InitializeParamsWithDomains("alice", "domain1", "data1", "read");
    TestEnforce(e, scope, false);

    scope = InitializeParamsWithDomains("bob", "domain2", "data2", "read");
    TestEnforce(e, scope, true);
    params = std::vector<std::string>{ "admin", "domain2", "data2", "read" };
    e.RemovePolicy(params);
    scope = InitializeParamsWithDomains("bob", "domain2", "data2", "read");
    TestEnforce(e, scope, false);
}

TEST(TestModelEnforcer, TestRBACModelWithDeny) {
    std::string model = "../../examples/rbac_with_deny_model.conf";
    std::string policy = "../../examples/rbac_with_deny_policy.csv";
    casbin::Enforcer e(model, policy);

    casbin::Scope scope = InitializeParams("alice", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestRBACModelWithOnlyDeny) {
    std::string model = "../../examples/rbac_with_not_deny_model.conf";
    std::string policy = "../../examples/rbac_with_deny_policy.csv";
    casbin::Enforcer e(model, policy);

    casbin::Scope scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, false);
}

TEST(TestModelEnforcer, TestRBACModelWithCustomData) {
    std::string model = "../../examples/rbac_model.conf";
    std::string policy = "../../examples/rbac_policy.csv";
    casbin::Enforcer e(model, policy);

    // You can add custom data to a grouping policy, Casbin will ignore it. It is only meaningful to the caller.
    // This feature can be used to store information like whether "bob" is an end user (so no subject will inherit "bob")
    // For Casbin, it is equivalent to: e.AddGroupingPolicy("bob", "data2_admin")
    std::vector<std::string> params{ "bob", "data2_admin", "custom_data" };
    e.AddGroupingPolicy(params);

    casbin::Scope scope = InitializeParams("alice", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, true);
    scope = InitializeParams("bob", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("bob", "data2", "write");
    TestEnforce(e, scope, true);

    // You should also take the custom data as a parameter when deleting a grouping policy.
    // e.RemoveGroupingPolicy("bob", "data2_admin") won't work.
    // Or you can remove it by using RemoveFilteredGroupingPolicy().
    params = std::vector<std::string>{ "bob", "data2_admin", "custom_data" };
    e.RemoveGroupingPolicy(params);

    scope = InitializeParams("alice", "data1", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("alice", "data2", "read");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "data2", "write");
    TestEnforce(e, scope, true);
    scope = InitializeParams("bob", "data1", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data1", "write");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "read");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "data2", "write");
    TestEnforce(e, scope, true);
}

TEST(TestModelEnforcer, TestRBACModelWithPattern) {
    std::string model = "../../examples/rbac_with_pattern_model.conf";
    std::string policy = "../../examples/rbac_with_pattern_policy.csv";
    casbin::Enforcer e(model, policy);

    // Here's a little confusing: the matching function here is not the custom function used in matcher.
    // It is the matching function used by "g" (and "g2", "g3" if any..)
    // You can see in policy that: "g2, /book/:id, book_group", so in "g2()" function in the matcher, instead
    // of checking whether "/book/:id" equals the obj: "/book/1", it checks whether the pattern matches.
    // You can see it as normal RBAC: "/book/:id" == "/book/1" becomes KeyMatch2("/book/:id", "/book/1")
    casbin::DefaultRoleManager* rm_tmp = dynamic_cast<casbin::DefaultRoleManager*>(e.rm.get());
    rm_tmp->AddMatchingFunc(casbin::KeyMatch2);
    casbin::Scope scope = InitializeParams("alice", "/book/1", "GET");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "/book/2", "GET");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "/pen/1", "GET");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "/pen/2", "GET");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "/book/1", "GET");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "/book/2", "GET");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "/pen/1", "GET");
    TestEnforce(e, scope, true);
    scope = InitializeParams("bob", "/pen/2", "GET");
    TestEnforce(e, scope, true);

    // AddMatchingFunc() is actually setting a function because only one function is allowed,
    // so when we set "KeyMatch3", we are actually replacing "KeyMatch2" with "KeyMatch3".
    rm_tmp->AddMatchingFunc(casbin::KeyMatch3);
    scope = InitializeParams("alice", "/book2/1", "GET");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "/book2/2", "GET");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "/pen2/1", "GET");
    TestEnforce(e, scope, true);
    scope = InitializeParams("alice", "/pen2/2", "GET");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "/book2/1", "GET");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "/book2/2", "GET");
    TestEnforce(e, scope, false);
    scope = InitializeParams("bob", "/pen2/1", "GET");
    TestEnforce(e, scope, true);
    scope = InitializeParams("bob", "/pen2/2", "GET");
    TestEnforce(e, scope, true);
}
/*
type testCustomRoleManager struct {}

func NewRoleManager() rbac.RoleManager{
    return &testCustomRoleManager{}
}
func(rm* testCustomRoleManager) Clear() error { return nil }
func(rm* testCustomRoleManager) AddLink(name1 string, name2 string, domain ...string) error {
        return nil
}
func(rm* testCustomRoleManager) DeleteLink(name1 string, name2 string, domain ...string) error {
    return nil
}
func(rm* testCustomRoleManager) HasLink(name1 string, name2 string, domain ...string) (bool, error) {
    if name1 == "alice" && name2 == "alice" {
        return true, nil
    }
    else if name1 == "alice" && name2 == "data2_admin" {
        return true, nil
    }
    else if name1 == "bob" && name2 == "bob" {
        return true, nil
    }
    return false, nil
}
func(rm* testCustomRoleManager) GetRoles(name string, domain ...string) ([]string, error) {
    return[]string{}, nil
}
func(rm* testCustomRoleManager) GetUsers(name string, domain ...string) ([]string, error) {
    return[]string{}, nil
}
func(rm* testCustomRoleManager) PrintRoles() error { return nil }
func TestRBACModelWithCustomRoleManager(t* testing.T) {
    e, _ : = NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
    e.SetRoleManager(NewRoleManager())
    e.LoadModel()
    _ = e.LoadPolicy()

    TestEnforce(e, "alice", "data1", "read", true)
    TestEnforce(e, "alice", "data1", "write", false)
    TestEnforce(e, "alice", "data2", "read", true)
    TestEnforce(e, "alice", "data2", "write", true)
    TestEnforce(e, "bob", "data1", "read", false)
    TestEnforce(e, "bob", "data1", "write", false)
    TestEnforce(e, "bob", "data2", "read", false)
    TestEnforce(e, "bob", "data2", "write", true)
}

type testResource struct {
    Name  string
        Owner string
}

func newTestResource(name string, owner string) testResource {
r: = testResource{}
    r.Name = name
    r.Owner = owner
    return r
}
func TestABACModel(t* testing.T) {
    e, _ : = NewEnforcer("examples/abac_model.conf")
        data1 : = newTestResource("data1", "alice")
        data2 : = newTestResource("data2", "bob")
        TestEnforce(e, "alice", data1, "read", true)
        TestEnforce(e, "alice", data1, "write", true)
        TestEnforce(e, "alice", data2, "read", false)
        TestEnforce(e, "alice", data2, "write", false)
        TestEnforce(e, "bob", data1, "read", false)
        TestEnforce(e, "bob", data1, "write", false)
        TestEnforce(e, "bob", data2, "read", true)
        TestEnforce(e, "bob", data2, "write", true)
}
func TestKeyMatchModel(t* testing.T) {
    e, _ : = NewEnforcer("examples/keymatch_model.conf", "examples/keymatch_policy.csv")
        TestEnforce(e, "alice", "/alice_data/resource1", "GET", true)
        TestEnforce(e, "alice", "/alice_data/resource1", "POST", true)
        TestEnforce(e, "alice", "/alice_data/resource2", "GET", true)
        TestEnforce(e, "alice", "/alice_data/resource2", "POST", false)
        TestEnforce(e, "alice", "/bob_data/resource1", "GET", false)
        TestEnforce(e, "alice", "/bob_data/resource1", "POST", false)
        TestEnforce(e, "alice", "/bob_data/resource2", "GET", false)
        TestEnforce(e, "alice", "/bob_data/resource2", "POST", false)
        TestEnforce(e, "bob", "/alice_data/resource1", "GET", false)
        TestEnforce(e, "bob", "/alice_data/resource1", "POST", false)
        TestEnforce(e, "bob", "/alice_data/resource2", "GET", true)
        TestEnforce(e, "bob", "/alice_data/resource2", "POST", false)
        TestEnforce(e, "bob", "/bob_data/resource1", "GET", false)
        TestEnforce(e, "bob", "/bob_data/resource1", "POST", true)
        TestEnforce(e, "bob", "/bob_data/resource2", "GET", false)
        TestEnforce(e, "bob", "/bob_data/resource2", "POST", true)
        TestEnforce(e, "cathy", "/cathy_data", "GET", true)
        TestEnforce(e, "cathy", "/cathy_data", "POST", true)
        TestEnforce(e, "cathy", "/cathy_data", "DELETE", false)
}
func TestKeyMatch2Model(t* testing.T) {
    e, _ : = NewEnforcer("examples/keymatch2_model.conf", "examples/keymatch2_policy.csv")
        TestEnforce(e, "alice", "/alice_data", "GET", false)
        TestEnforce(e, "alice", "/alice_data/resource1", "GET", true)
        TestEnforce(e, "alice", "/alice_data2/myid", "GET", false)
        TestEnforce(e, "alice", "/alice_data2/myid/using/res_id", "GET", true)
}
func CustomFunction(key1 string, key2 string) bool{
    if key1 == "/alice_data2/myid/using/res_id" && key2 == "/alice_data/:resource" {
        return true
    }
    else if key1 == "/alice_data2/myid/using/res_id" && key2 == "/alice_data2/:id/using/:resId" {
    return true
}
else {
return false
}
}
    func CustomFunctionWrapper(args ...interface {}) (interface {}, error) {
key1: = args[0].(std::string)
    key2 : = args[1].(std::string)
    return bool(CustomFunction(key1, key2)), nil
}
func TestKeyMatchCustomModel(t* testing.T) {
    e, _ : = NewEnforcer("examples/keymatch_custom_model.conf", "examples/keymatch2_policy.csv")
        e.AddFunction("keyMatchCustom", CustomFunctionWrapper)
        TestEnforce(e, "alice", "/alice_data2/myid", "GET", false)
        TestEnforce(e, "alice", "/alice_data2/myid/using/res_id", "GET", true)
}
func TestIPMatchModel(t* testing.T) {
    e, _ : = NewEnforcer("examples/ipmatch_model.conf", "examples/ipmatch_policy.csv")
        TestEnforce(e, "192.168.2.123", "data1", "read", true)
        TestEnforce(e, "192.168.2.123", "data1", "write", false)
        TestEnforce(e, "192.168.2.123", "data2", "read", false)
        TestEnforce(e, "192.168.2.123", "data2", "write", false)
        TestEnforce(e, "192.168.0.123", "data1", "read", false)
        TestEnforce(e, "192.168.0.123", "data1", "write", false)
        TestEnforce(e, "192.168.0.123", "data2", "read", false)
        TestEnforce(e, "192.168.0.123", "data2", "write", false)
        TestEnforce(e, "10.0.0.5", "data1", "read", false)
        TestEnforce(e, "10.0.0.5", "data1", "write", false)
        TestEnforce(e, "10.0.0.5", "data2", "read", false)
        TestEnforce(e, "10.0.0.5", "data2", "write", true)
        TestEnforce(e, "192.168.0.1", "data1", "read", false)
        TestEnforce(e, "192.168.0.1", "data1", "write", false)
        TestEnforce(e, "192.168.0.1", "data2", "read", false)
        TestEnforce(e, "192.168.0.1", "data2", "write", false)
}
func TestGlobMatchModel(t* testing.T) {
    e, _ : = NewEnforcer("examples/glob_model.conf", "examples/glob_policy.csv")
        TestEnforce(e, "u1", "/foo/", "read", true)
        TestEnforce(e, "u1", "/foo", "read", false)
        TestEnforce(e, "u1", "/foo/subprefix", "read", true)
        TestEnforce(e, "u1", "foo", "read", false)
        TestEnforce(e, "u2", "/foosubprefix", "read", true)
        TestEnforce(e, "u2", "/foo/subprefix", "read", false)
        TestEnforce(e, "u2", "foo", "read", false)
        TestEnforce(e, "u3", "/prefix/foo/subprefix", "read", true)
        TestEnforce(e, "u3", "/prefix/foo/", "read", true)
        TestEnforce(e, "u3", "/prefix/foo", "read", false)
        TestEnforce(e, "u4", "/foo", "read", false)
        TestEnforce(e, "u4", "foo", "read", true)
}
func TestPriorityModel(t* testing.T) {
    e, _ : = NewEnforcer("examples/priority_model.conf", "examples/priority_policy.csv")
        TestEnforce(e, "alice", "data1", "read", true)
        TestEnforce(e, "alice", "data1", "write", false)
        TestEnforce(e, "alice", "data2", "read", false)
        TestEnforce(e, "alice", "data2", "write", false)
        TestEnforce(e, "bob", "data1", "read", false)
        TestEnforce(e, "bob", "data1", "write", false)
        TestEnforce(e, "bob", "data2", "read", true)
        TestEnforce(e, "bob", "data2", "write", false)
}
func TestPriorityModelIndeterminate(t* testing.T) {
    e, _ : = NewEnforcer("examples/priority_model.conf", "examples/priority_indeterminate_policy.csv")
        TestEnforce(e, "alice", "data1", "read", false)
}
func TestRBACModelInMultiLines(t* testing.T) {
    e, _ : = NewEnforcer("examples/rbac_model_in_multi_line.conf", "examples/rbac_policy.csv")
        TestEnforce(e, "alice", "data1", "read", true)
        TestEnforce(e, "alice", "data1", "write", false)
        TestEnforce(e, "alice", "data2", "read", true)
        TestEnforce(e, "alice", "data2", "write", true)
        TestEnforce(e, "bob", "data1", "read", false)
        TestEnforce(e, "bob", "data1", "write", false)
        TestEnforce(e, "bob", "data2", "read", false)
        TestEnforce(e, "bob", "data2", "write", true)
}
type testSub struct {
    Name string
        Age  int
}
func newTestSubject(name string, age int) testSub {
s: = testSub{}
    s.Name = name
    s.Age = age
    return s
}
func TestABACPolicy(t* testing.T) {
    e, _ : = NewEnforcer("examples/abac_rule_model.conf", "examples/abac_rule_policy.csv")
        sub1 : = newTestSubject("alice", 16)
        sub2 : = newTestSubject("alice", 20)
        sub3 : = newTestSubject("alice", 65)
        TestEnforce(e, sub1, "/data1", "read", false)
        TestEnforce(e, sub1, "/data2", "read", false)
        TestEnforce(e, sub1, "/data1", "write", false)
        TestEnforce(e, sub1, "/data2", "write", true)
        TestEnforce(e, sub2, "/data1", "read", true)
        TestEnforce(e, sub2, "/data2", "read", false)
        TestEnforce(e, sub2, "/data1", "write", false)
        TestEnforce(e, sub2, "/data2", "write", true)
        TestEnforce(e, sub3, "/data1", "read", true)
        TestEnforce(e, sub3, "/data2", "read", false)
        TestEnforce(e, sub3, "/data1", "write", false)
        TestEnforce(e, sub3, "/data2", "write", false)
}
func TestCommentModel(t* testing.T) {
    e, _ : = NewEnforcer("examples/comment_model.conf", "examples/basic_policy.csv")
        TestEnforce(e, "alice", "data1", "read", true)
        TestEnforce(e, "alice", "data1", "write", false)
        TestEnforce(e, "alice", "data2", "read", false)
        TestEnforce(e, "alice", "data2", "write", false)
        TestEnforce(e, "bob", "data1", "read", false)
        TestEnforce(e, "bob", "data1", "write", false)
        TestEnforce(e, "bob", "data2", "read", false)
        TestEnforce(e, "bob", "data2", "write", true)
}
*/

}
