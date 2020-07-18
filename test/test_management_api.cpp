#pragma once

#include "pch.h"

#include <enforcer.h>
#include <persist.h>
#include <config.h>
#include <util.h>
#include <exception.h>

using namespace std;

namespace test_management_api
{
    TEST_CLASS(TestManagementAPI)
    {
        public:

            TEST_METHOD(TestGetList) {
                string model = "../../examples/rbac_model.conf";
                string policy = "../../examples/rbac_policy.csv";
                shared_ptr<Enforcer> e = Enforcer :: NewEnforcer(model, policy);

                Assert::IsTrue(ArrayEquals(vector<string>{ "alice", "bob", "data2_admin" }, e->GetAllSubjects()));
                Assert::IsTrue(ArrayEquals(vector<string>{ "data1", "data2" }, e->GetAllObjects()));
                Assert::IsTrue(ArrayEquals(vector<string>{ "read", "write" }, e->GetAllActions()));
                Assert::IsTrue(ArrayEquals(vector<string>{ "data2_admin" }, e->GetAllRoles()));
            }

            void TestGetPolicy(shared_ptr<Enforcer> e, vector<vector<string>> res) {
                vector<vector<string>> my_res;
                my_res = e->GetPolicy();

                int count = 0;
                for (int i = 0; i < my_res.size(); i++) {
                    for (int j = 0; j < res.size(); j++) {
                        if (ArrayEquals(my_res[i], res[j]))
                            count++;
                    }
                }

                if (count == res.size())
                    Assert::IsTrue(true);
            }

            void TestGetFilteredPolicy(shared_ptr<Enforcer> e, int field_index, vector<vector<string>> res, vector<string> field_values) {
                vector<vector<string>> my_res = e->GetFilteredPolicy(field_index, field_values);
                for (int i = 0; i < res.size(); i++) {
                    Assert::IsTrue(ArrayEquals(my_res[i], res[i]));
                }
            }

            void TestGetGroupingPolicy(shared_ptr<Enforcer> e, vector<vector<string>> res) {
                vector<vector<string>> my_res = e->GetGroupingPolicy();

                for (int i = 0; i < my_res.size(); i++) {
                    Assert::IsTrue(ArrayEquals(my_res[i], res[i]));
                }
            }

            void TestGetFilteredGroupingPolicy(shared_ptr<Enforcer> e, int field_index, vector<vector<string>> res, vector<string> field_values) {
                vector<vector<string>> my_res = e->GetFilteredGroupingPolicy(field_index, field_values);

                for (int i = 0; i < my_res.size(); i++) {
                    Assert::IsTrue(ArrayEquals(my_res[i], res[i]));
                }
            }

            void TestHasPolicy(shared_ptr<Enforcer> e, vector<string> policy, bool res) {
                bool my_res = e->HasPolicy(policy);
                Assert::AreEqual(res, my_res);
            }

            void TestHasGroupingPolicy(shared_ptr<Enforcer> e, vector<string> policy, bool res) {
                bool my_res = e->HasGroupingPolicy(policy);
                Assert::AreEqual(res, my_res);
            }

            TEST_METHOD(TestGetPolicyAPI) {
                string model = "../../examples/rbac_model.conf";
                string policy = "../../examples/rbac_policy.csv";
                shared_ptr<Enforcer> e = Enforcer::NewEnforcer(model, policy);

                TestGetPolicy(e, vector<vector<string>>{
                    {"alice", "data1", "read"},
                    { "bob", "data2", "write" },
                    { "data2_admin", "data2", "read" },
                    { "data2_admin", "data2", "write" }});

                TestGetFilteredPolicy(e, 0, vector<vector<string>>{ {"alice", "data1", "read"} }, vector<string>{"alice"});
                TestGetFilteredPolicy(e, 0, vector<vector<string>>{ {"bob", "data2", "write"}}, vector<string>{"bob"});
                TestGetFilteredPolicy(e, 0, vector<vector<string>>{ {"data2_admin", "data2", "read"}, { "data2_admin", "data2", "write" }}, vector<string>{"data2_admin"});
                TestGetFilteredPolicy(e, 1, vector<vector<string>>{ {"alice", "data1", "read"}}, vector<string>{"data1"});
                TestGetFilteredPolicy(e, 1, vector<vector<string>>{ {"bob", "data2", "write"}, { "data2_admin", "data2", "read" }, { "data2_admin", "data2", "write" }}, vector<string>{"data2"});
                TestGetFilteredPolicy(e, 2, vector<vector<string>>{ {"alice", "data1", "read"}, { "data2_admin", "data2", "read" }}, vector<string>{"read"});
                TestGetFilteredPolicy(e, 2, vector<vector<string>>{ {"bob", "data2", "write"}, { "data2_admin", "data2", "write" }}, vector<string>{"write"});

                TestGetFilteredPolicy(e, 0, vector<vector<string>>{ {"data2_admin", "data2", "read"}, { "data2_admin", "data2", "write" }}, vector<string>{"data2_admin", "data2"});
                // Note: "" (empty string) in fieldValues means matching all values.
                TestGetFilteredPolicy(e, 0, vector<vector<string>>{ {"data2_admin", "data2", "read"}}, vector<string>{"data2_admin", "", "read"});
                TestGetFilteredPolicy(e, 1, vector<vector<string>>{ {"bob", "data2", "write"}, { "data2_admin", "data2", "write" }}, vector<string>{"data2", "write"});

                TestHasPolicy(e, vector<string>{"alice", "data1", "read"}, true);
                TestHasPolicy(e, vector<string>{"bob", "data2", "write"}, true);
                TestHasPolicy(e, vector<string>{"alice", "data2", "read"}, false);
                TestHasPolicy(e, vector<string>{"bob", "data3", "write"}, false);

                TestGetGroupingPolicy(e, vector<vector<string>>{ {"alice", "data2_admin"}});

                TestGetFilteredGroupingPolicy(e, 0, vector<vector<string>>{ {"alice", "data2_admin"}}, vector < string>{"alice"});
                TestGetFilteredGroupingPolicy(e, 0, vector<vector<string>>{}, vector < string>{"bob"});
                TestGetFilteredGroupingPolicy(e, 1, vector<vector<string>>{}, vector<string>{"data1_admin"});
                TestGetFilteredGroupingPolicy(e, 1, vector<vector<string>>{ {"alice", "data2_admin"}}, vector<string>{"data2_admin"});
                // Note: "" (empty string) in fieldValues means matching all values.
                TestGetFilteredGroupingPolicy(e, 0, vector<vector<string>>{ {"alice", "data2_admin"}}, vector<string>{"", "data2_admin"});

                TestHasGroupingPolicy(e, vector<string>{"alice", "data2_admin"}, true);
                TestHasGroupingPolicy(e, vector<string>{"bob", "data2_admin"}, false);
            }


            TEST_METHOD(TestModifyPolicyAPI) {
                string model = "../../examples/rbac_model.conf";
                string policy = "../../examples/rbac_policy.csv";
                shared_ptr<Adapter> adapter = shared_ptr<Adapter>(BatchFileAdapter::NewAdapter(policy));
                shared_ptr<Enforcer> e = Enforcer::NewEnforcer(model, adapter);

                TestGetPolicy(e, vector<vector<string>>{
                    {"alice", "data1", "read"},
                    { "bob", "data2", "write" },
                    { "data2_admin", "data2", "read" },
                    { "data2_admin", "data2", "write" }});

                e->RemovePolicy(vector<string>{"alice", "data1", "read"});
                e->RemovePolicy(vector<string>{"bob", "data2", "write"});
                e->RemovePolicy(vector<string>{"alice", "data1", "read"});
                e->AddPolicy(vector<string>{"eve", "data3", "read"});
                e->AddPolicy(vector<string>{"eve", "data3", "read"});

                vector<vector<string>>rules{
                    {"jack", "data4", "read"},
                    {"katy", "data4", "write"},
                    {"leyo", "data4", "read"},
                    {"ham", "data4", "write"},
                };

                e->AddPolicies(rules);
                e->AddPolicies(rules);

                TestGetPolicy(e, vector<vector<string>>{
                    {"data2_admin", "data2", "read"},
                    { "data2_admin", "data2", "write" },
                    { "eve", "data3", "read" },
                    { "jack", "data4", "read" },
                    { "katy", "data4", "write" },
                    { "leyo", "data4", "read" },
                    { "ham", "data4", "write" }});

                e->RemovePolicies(rules);
                e->RemovePolicies(rules);

                vector<string>named_policy{ "eve", "data3", "read" };
                e->RemoveNamedPolicy("p", named_policy);
                e->AddNamedPolicy("p", named_policy);

                TestGetPolicy(e, vector<vector<string>>{
                    {"data2_admin", "data2", "read"},
                    { "data2_admin", "data2", "write" },
                    { "eve", "data3", "read" }});

                e->RemoveFilteredPolicy(1, vector<string>{"data2"});

                TestGetPolicy(e, vector<vector<string>>{ {"eve", "data3", "read"}});
            }

            TEST_METHOD(TestModifyGroupingPolicyAPI) {
                string model = "../../examples/rbac_model.conf";
                string policy = "../../examples/rbac_policy.csv";
                shared_ptr<Adapter> adapter = shared_ptr<Adapter>(BatchFileAdapter::NewAdapter(policy));
                shared_ptr<Enforcer> e = Enforcer::NewEnforcer(model, adapter);

                Assert::IsTrue(ArrayEquals(vector<string>{"data2_admin"}, e->GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(vector<string>{}, e->GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(vector<string>{}, e->GetRolesForUser("eve")));
                Assert::IsTrue(ArrayEquals(vector<string>{}, e->GetRolesForUser("non_exist")));

                e->RemoveGroupingPolicy(vector<string>{"alice", "data2_admin"});
                e->AddGroupingPolicy(vector<string>{"bob", "data1_admin"});
                e->AddGroupingPolicy(vector<string>{"eve", "data3_admin"});

                vector<vector<string>> grouping_rules{
                    {"ham", "data4_admin"},
                    {"jack", "data5_admin"},
                };

                e->AddGroupingPolicies(grouping_rules);
                Assert::IsTrue(ArrayEquals(vector<string>{"data4_admin"}, e->GetRolesForUser("ham")));
                Assert::IsTrue(ArrayEquals(vector<string>{"data5_admin"}, e->GetRolesForUser("jack")));
                e->RemoveGroupingPolicies(grouping_rules);

                Assert::IsTrue(ArrayEquals(vector<string>{}, e->GetRolesForUser("alice")));
                vector<string> named_grouping_policy{ "alice", "data2_admin" };
                Assert::IsTrue(ArrayEquals(vector<string>{}, e->GetRolesForUser("alice")));
                e->AddNamedGroupingPolicy("g", named_grouping_policy);
                Assert::IsTrue(ArrayEquals(vector<string>{"data2_admin"}, e->GetRolesForUser("alice")));
                e->RemoveNamedGroupingPolicy("g", named_grouping_policy);

                e->AddNamedGroupingPolicies("g", grouping_rules);
                e->AddNamedGroupingPolicies("g", grouping_rules);
                Assert::IsTrue(ArrayEquals(vector<string>{"data4_admin"}, e->GetRolesForUser("ham")));
                Assert::IsTrue(ArrayEquals(vector<string>{"data5_admin"}, e->GetRolesForUser("jack")));
                e->RemoveNamedGroupingPolicies("g", grouping_rules);
                e->RemoveNamedGroupingPolicies("g", grouping_rules);

                Assert::IsTrue(ArrayEquals(vector<string>{}, e->GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(vector<string>{"data1_admin"}, e->GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(vector<string>{"data3_admin"}, e->GetRolesForUser("eve")));
                Assert::IsTrue(ArrayEquals(vector<string>{}, e->GetRolesForUser("non_exist")));

                Assert::IsTrue(ArrayEquals(vector<string>{"bob"}, e->GetUsersForRole("data1_admin")));
                try {
                    e->GetUsersForRole("data2_admin", vector<string>{});
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                Assert::IsTrue(ArrayEquals(vector<string>{"eve"}, e->GetUsersForRole("data3_admin")));
                
                e->RemoveFilteredGroupingPolicy(0, vector<string>{"bob"});

                Assert::IsTrue(ArrayEquals(vector<string>{}, e->GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(vector<string>{}, e->GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(vector<string>{"data3_admin"}, e->GetRolesForUser("eve")));
                Assert::IsTrue(ArrayEquals(vector<string>{}, e->GetRolesForUser("non_exist")));

                try {
                    e->GetUsersForRole("data1_admin");
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                try {
                    e->GetUsersForRole("data2_admin");
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                Assert::IsTrue(ArrayEquals(vector<string>{"eve"}, e->GetUsersForRole("data3_admin")));
            }
    };
}