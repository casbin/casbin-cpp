/*
* Copyright 2021 The casbin Authors. All Rights Reserved.
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
* This is a test file for testing the Management API in casbin
*/

#include <gtest/gtest.h>
#include <casbin/casbin.h>

namespace {

TEST(TestManagementAPI, TestGetList) {
    std::string model = "../../examples/rbac_model.conf";
    std::string policy = "../../examples/rbac_policy.csv";
    casbin::Enforcer e(model, policy);

    ASSERT_TRUE(casbin::ArrayEquals({ "alice", "bob", "data2_admin" }, e.GetAllSubjects()));
    ASSERT_TRUE(casbin::ArrayEquals({ "data1", "data2" }, e.GetAllObjects()));
    ASSERT_TRUE(casbin::ArrayEquals({ "read", "write" }, e.GetAllActions()));
    ASSERT_TRUE(casbin::ArrayEquals({ "data2_admin" }, e.GetAllRoles()));
}

void TestGetPolicy(casbin::Enforcer& e, const std::vector<std::vector<std::string>>& res) {
    std::vector<std::vector<std::string>> my_res;
    my_res = e.GetPolicy();

    int count = 0;
    for (auto my_response : my_res) {
        for (auto response : res) {
            if (casbin::ArrayEquals(my_response, response))
                ++count;
        }
    }

    ASSERT_EQ(count, res.size());
}

void TestGetFilteredPolicy(casbin::Enforcer& e, int field_index, const std::vector<std::vector<std::string>>& res, const std::vector<std::string>& field_values) {
    auto my_res = e.GetFilteredPolicy(field_index, field_values);
    for (int i = 0; i < res.size(); i++)
        ASSERT_TRUE(casbin::ArrayEquals(my_res[i], res[i]));
}

void TestGetGroupingPolicy(casbin::Enforcer& e, const std::vector<std::vector<std::string>>& res) {
    auto my_res = e.GetGroupingPolicy();

    for (int i = 0; i < my_res.size(); i++)
        ASSERT_TRUE(casbin::ArrayEquals(my_res[i], res[i]));
}

void TestGetFilteredGroupingPolicy(casbin::Enforcer& e, int field_index, const std::vector<std::vector<std::string>>& res, const std::vector<std::string>& field_values) {
    auto my_res = e.GetFilteredGroupingPolicy(field_index, field_values);

    for (int i = 0; i < my_res.size(); i++) {
        ASSERT_TRUE(casbin::ArrayEquals(my_res[i], res[i]));
    }
}

void TestHasPolicy(casbin::Enforcer e, const std::vector<std::string>& policy, bool res) {
    bool my_res = e.HasPolicy(policy);
    ASSERT_EQ(res, my_res);
}

void TestHasGroupingPolicy(casbin::Enforcer& e, const std::vector<std::string>& policy, bool res) {
    bool my_res = e.HasGroupingPolicy(policy);
    ASSERT_EQ(res, my_res);
}

TEST(TestManagementAPI, TestGetPolicyAPI) {
    std::string model = "../../examples/rbac_model.conf";
    std::string policy = "../../examples/rbac_policy.csv";
    casbin::Enforcer e(model, policy);

    TestGetPolicy(e, {
        {"alice", "data1", "read"},
        { "bob", "data2", "write" },
        { "data2_admin", "data2", "read" },
        { "data2_admin", "data2", "write" }
    });

    TestGetFilteredPolicy(e, 0, { {"alice", "data1", "read"} }, {"alice"});
    TestGetFilteredPolicy(e, 0, { {"bob", "data2", "write"}}, {"bob"});
    TestGetFilteredPolicy(e, 0, { {"data2_admin", "data2", "read"}, { "data2_admin", "data2", "write" }}, {"data2_admin"});
    TestGetFilteredPolicy(e, 1, { {"alice", "data1", "read"}}, {"data1"});
    TestGetFilteredPolicy(e, 1, { {"bob", "data2", "write"}, { "data2_admin", "data2", "read" }, { "data2_admin", "data2", "write" }}, {"data2"});
    TestGetFilteredPolicy(e, 2, { {"alice", "data1", "read"}, { "data2_admin", "data2", "read" }}, {"read"});
    TestGetFilteredPolicy(e, 2, { {"bob", "data2", "write"}, { "data2_admin", "data2", "write" }}, {"write"});

    TestGetFilteredPolicy(e, 0, { {"data2_admin", "data2", "read"}, { "data2_admin", "data2", "write" }}, {"data2_admin", "data2"});
    // Note: "" (empty string) in fieldValues means matching all values.
    TestGetFilteredPolicy(e, 0, { {"data2_admin", "data2", "read"}}, {"data2_admin", "", "read"});
    TestGetFilteredPolicy(e, 1, { {"bob", "data2", "write"}, { "data2_admin", "data2", "write" }}, {"data2", "write"});

    TestHasPolicy(e, {"alice", "data1", "read"}, true);
    TestHasPolicy(e, {"bob", "data2", "write"}, true);
    TestHasPolicy(e, {"alice", "data2", "read"}, false);
    TestHasPolicy(e, {"bob", "data3", "write"}, false);

    TestGetGroupingPolicy(e, std::vector<std::vector<std::string>>{ {"alice", "data2_admin"}});

    TestGetFilteredGroupingPolicy(e, 0, {{"alice", "data2_admin"}}, {"alice"});
    TestGetFilteredGroupingPolicy(e, 0, {}, {"bob"});
    TestGetFilteredGroupingPolicy(e, 1, {}, {"data1_admin"});
    TestGetFilteredGroupingPolicy(e, 1, { {"alice", "data2_admin"}}, {"data2_admin"});
                // Note: "" (empty string) in fieldValues means matching all values.
    TestGetFilteredGroupingPolicy(e, 0, { {"alice", "data2_admin"}}, {"", "data2_admin"});

    TestHasGroupingPolicy(e, {"alice", "data2_admin"}, true);
    TestHasGroupingPolicy(e, {"bob", "data2_admin"}, false);
}


TEST(TestManagementAPI, TestModifyPolicyAPI) {
    std::string model = "../../examples/rbac_model.conf";
    std::string policy = "../../examples/rbac_policy.csv";
    std::shared_ptr<casbin::Adapter> adapter = std::make_shared<casbin::BatchFileAdapter>(policy);
    casbin::Enforcer e(model, adapter);

    TestGetPolicy(e, {
        {"alice", "data1", "read"},
        {"bob", "data2", "write"},
        {"data2_admin", "data2", "read"},
        {"data2_admin", "data2", "write"}
    });

    e.RemovePolicy({"alice", "data1", "read"});
    e.RemovePolicy({"bob", "data2", "write"});
    e.RemovePolicy({"alice", "data1", "read"});
    e.AddPolicy({"eve", "data3", "read"});
    e.AddPolicy({"eve", "data3", "read"});

    std::vector<std::vector<std::string>> rules {
                    {"jack", "data4", "read"},
                    {"katy", "data4", "write"},
                    {"leyo", "data4", "read"},
                    {"ham", "data4", "write"},
    };

    e.AddPolicies(rules);
    e.AddPolicies(rules);

    TestGetPolicy(e, {
        {"data2_admin", "data2", "read"},
        { "data2_admin", "data2", "write" },
        { "eve", "data3", "read" },
        { "jack", "data4", "read" },
        { "katy", "data4", "write" },
        { "leyo", "data4", "read" },
        { "ham", "data4", "write" }
    });

    e.RemovePolicies(rules);
    e.RemovePolicies(rules);

    std::vector<std::string> named_policy{ "eve", "data3", "read" };
    e.RemoveNamedPolicy("p", named_policy);
    e.AddNamedPolicy("p", named_policy);

    TestGetPolicy(e, {
        {"data2_admin", "data2", "read"},
        { "data2_admin", "data2", "write" },
        { "eve", "data3", "read" }
    });

    e.RemoveFilteredPolicy(1, {"data2"});

    TestGetPolicy(e, { {"eve", "data3", "read"}});

    e.UpdatePolicy({"eve", "data3", "read"}, {"eve", "data3", "write"});
    TestGetPolicy(e, {{"eve", "data3", "write"}});
                
    e.AddPolicies(rules);
    e.UpdatePolicies({ 
        {"eve", "data3", "write"}, 
        {"leyo", "data4", "read"}, 
        {"katy", "data4", "write"} 
    }, {
        {"eve", "data3", "read"},
        {"leyo", "data4", "write"},
        {"katy", "data1", "write"}
    });

    TestGetPolicy(e, {
        {"eve", "data3", "read"},
        {"leyo", "data4", "write"},
        {"katy", "data1", "write"}
    });
}

TEST(TestManagementAPI, TestModifyGroupingPolicyAPI) {
    std::string model = "../../examples/rbac_model.conf";
    std::string policy = "../../examples/rbac_policy.csv";
    std::shared_ptr<casbin::Adapter> adapter = std::make_shared<casbin::BatchFileAdapter>(policy);
    casbin::Enforcer e(model, adapter);

    ASSERT_TRUE(casbin::ArrayEquals({"data2_admin"}, e.GetRolesForUser("alice")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("bob")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("eve")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("non_exist")));

    e.RemoveGroupingPolicy({"alice", "data2_admin"});
    e.AddGroupingPolicy({"bob", "data1_admin"});
    e.AddGroupingPolicy({"eve", "data3_admin"});

    std::vector<std::vector<std::string>> grouping_rules {
        {"ham", "data4_admin"},
        {"jack", "data5_admin"},
    };

    e.AddGroupingPolicies(grouping_rules);
    ASSERT_TRUE(casbin::ArrayEquals({"data4_admin"}, e.GetRolesForUser("ham")));
    ASSERT_TRUE(casbin::ArrayEquals({"data5_admin"}, e.GetRolesForUser("jack")));
    e.RemoveGroupingPolicies(grouping_rules);

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("alice")));
    std::vector<std::string> named_grouping_policy{ "alice", "data2_admin" };
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("alice")));
    e.AddNamedGroupingPolicy("g", named_grouping_policy);
    ASSERT_TRUE(casbin::ArrayEquals({"data2_admin"}, e.GetRolesForUser("alice")));
    e.RemoveNamedGroupingPolicy("g", named_grouping_policy);

    e.AddNamedGroupingPolicies("g", grouping_rules);
    e.AddNamedGroupingPolicies("g", grouping_rules);
    ASSERT_TRUE(casbin::ArrayEquals({"data4_admin"}, e.GetRolesForUser("ham")));
    ASSERT_TRUE(casbin::ArrayEquals({"data5_admin"}, e.GetRolesForUser("jack")));
    e.RemoveNamedGroupingPolicies("g", grouping_rules);
    e.RemoveNamedGroupingPolicies("g", grouping_rules);

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("alice")));
    ASSERT_TRUE(casbin::ArrayEquals({"data1_admin"}, e.GetRolesForUser("bob")));
    ASSERT_TRUE(casbin::ArrayEquals({"data3_admin"}, e.GetRolesForUser("eve")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("non_exist")));

    ASSERT_TRUE(casbin::ArrayEquals({"bob"}, e.GetUsersForRole("data1_admin")));
    try {
        e.GetUsersForRole("data2_admin", {});
    }
    catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }
    ASSERT_TRUE(casbin::ArrayEquals({"eve"}, e.GetUsersForRole("data3_admin")));
                
    e.RemoveFilteredGroupingPolicy(0, {"bob"});

    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("alice")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("bob")));
    ASSERT_TRUE(casbin::ArrayEquals({"data3_admin"}, e.GetRolesForUser("eve")));
    ASSERT_TRUE(casbin::ArrayEquals({}, e.GetRolesForUser("non_exist")));

    try {
        e.GetUsersForRole("data1_admin");
    }
    catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }
    try {
        e.GetUsersForRole("data2_admin");
    }
    catch (casbin::CasbinRBACException e) {
        ASSERT_TRUE(true);
    }
    ASSERT_TRUE(casbin::ArrayEquals({"eve"}, e.GetUsersForRole("data3_admin")));

    ASSERT_TRUE(e.AddGroupingPolicy({"data3_admin", "data4_admin"}));
    e.UpdateGroupingPolicy({"eve", "data3_admin"}, {"eve", "admin"});
    e.UpdateGroupingPolicy({"data3_admin", "data4_admin"}, {"admin", "data4_admin"});

    // ASSERT_TRUE(ArrayEquals({"admin"}, e.GetUsersForRole("data4_admin")));
    ASSERT_TRUE(casbin::ArrayEquals({"eve"}, e.GetUsersForRole("admin")));

    ASSERT_TRUE(casbin::ArrayEquals({"admin"}, e.GetRolesForUser("eve")));
    ASSERT_TRUE(casbin::ArrayEquals({"data4_admin"}, e.GetRolesForUser("admin")));
}

} // namespace
