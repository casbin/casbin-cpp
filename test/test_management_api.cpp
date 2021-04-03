#include "pch.h"

#ifndef TEST_MANAGEMENT_API_CPP
#define TEST_MANAGEMENT_API_CPP


#include <enforcer.h>
#include <persist.h>
#include <config.h>
#include <util.h>
#include <exception.h>

namespace test_management_api
{
    using namespace casbin;

    TEST_CLASS(TestManagementAPI)
    {
        public:

            TEST_METHOD(TestGetList) {
                std::string model = "../../examples/rbac_model.conf";
                std::string policy = "../../examples/rbac_policy.csv";
                Enforcer e = Enforcer(model, policy);

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "alice", "bob", "data2_admin" }, e.GetAllSubjects()));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "data1", "data2" }, e.GetAllObjects()));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "read", "write" }, e.GetAllActions()));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "data2_admin" }, e.GetAllRoles()));
            }

            void TestGetPolicy(Enforcer e, std::vector<std::vector<std::string>> res) {
                std::vector<std::vector<std::string>> my_res;
                my_res = e.GetPolicy();

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

            void TestGetFilteredPolicy(Enforcer e, int field_index, std::vector<std::vector<std::string>> res, std::vector<std::string> field_values) {
                std::vector<std::vector<std::string>> my_res = e.GetFilteredPolicy(field_index, field_values);
                for (int i = 0; i < res.size(); i++) {
                    Assert::IsTrue(ArrayEquals(my_res[i], res[i]));
                }
            }

            void TestGetGroupingPolicy(Enforcer e, std::vector<std::vector<std::string>> res) {
                std::vector<std::vector<std::string>> my_res = e.GetGroupingPolicy();

                for (int i = 0; i < my_res.size(); i++) {
                    Assert::IsTrue(ArrayEquals(my_res[i], res[i]));
                }
            }

            void TestGetFilteredGroupingPolicy(Enforcer e, int field_index, std::vector<std::vector<std::string>> res, std::vector<std::string> field_values) {
                std::vector<std::vector<std::string>> my_res = e.GetFilteredGroupingPolicy(field_index, field_values);

                for (int i = 0; i < my_res.size(); i++) {
                    Assert::IsTrue(ArrayEquals(my_res[i], res[i]));
                }
            }

            void TestHasPolicy(Enforcer e, std::vector<std::string> policy, bool res) {
                bool my_res = e.HasPolicy(policy);
                Assert::AreEqual(res, my_res);
            }

            void TestHasGroupingPolicy(Enforcer e, std::vector<std::string> policy, bool res) {
                bool my_res = e.HasGroupingPolicy(policy);
                Assert::AreEqual(res, my_res);
            }

            TEST_METHOD(TestGetPolicyAPI) {
                std::string model = "../../examples/rbac_model.conf";
                std::string policy = "../../examples/rbac_policy.csv";
                Enforcer e = Enforcer(model, policy);

                TestGetPolicy(e, std::vector<std::vector<std::string>>{
                    {"alice", "data1", "read"},
                    { "bob", "data2", "write" },
                    { "data2_admin", "data2", "read" },
                    { "data2_admin", "data2", "write" }});

                TestGetFilteredPolicy(e, 0, std::vector<std::vector<std::string>>{ {"alice", "data1", "read"} }, std::vector<std::string>{"alice"});
                TestGetFilteredPolicy(e, 0, std::vector<std::vector<std::string>>{ {"bob", "data2", "write"}}, std::vector<std::string>{"bob"});
                TestGetFilteredPolicy(e, 0, std::vector<std::vector<std::string>>{ {"data2_admin", "data2", "read"}, { "data2_admin", "data2", "write" }}, std::vector<std::string>{"data2_admin"});
                TestGetFilteredPolicy(e, 1, std::vector<std::vector<std::string>>{ {"alice", "data1", "read"}}, std::vector<std::string>{"data1"});
                TestGetFilteredPolicy(e, 1, std::vector<std::vector<std::string>>{ {"bob", "data2", "write"}, { "data2_admin", "data2", "read" }, { "data2_admin", "data2", "write" }}, std::vector<std::string>{"data2"});
                TestGetFilteredPolicy(e, 2, std::vector<std::vector<std::string>>{ {"alice", "data1", "read"}, { "data2_admin", "data2", "read" }}, std::vector<std::string>{"read"});
                TestGetFilteredPolicy(e, 2, std::vector<std::vector<std::string>>{ {"bob", "data2", "write"}, { "data2_admin", "data2", "write" }}, std::vector<std::string>{"write"});

                TestGetFilteredPolicy(e, 0, std::vector<std::vector<std::string>>{ {"data2_admin", "data2", "read"}, { "data2_admin", "data2", "write" }}, std::vector<std::string>{"data2_admin", "data2"});
                // Note: "" (empty string) in fieldValues means matching all values.
                TestGetFilteredPolicy(e, 0, std::vector<std::vector<std::string>>{ {"data2_admin", "data2", "read"}}, std::vector<std::string>{"data2_admin", "", "read"});
                TestGetFilteredPolicy(e, 1, std::vector<std::vector<std::string>>{ {"bob", "data2", "write"}, { "data2_admin", "data2", "write" }}, std::vector<std::string>{"data2", "write"});

                TestHasPolicy(e, std::vector<std::string>{"alice", "data1", "read"}, true);
                TestHasPolicy(e, std::vector<std::string>{"bob", "data2", "write"}, true);
                TestHasPolicy(e, std::vector<std::string>{"alice", "data2", "read"}, false);
                TestHasPolicy(e, std::vector<std::string>{"bob", "data3", "write"}, false);

                TestGetGroupingPolicy(e, std::vector<std::vector<std::string>>{ {"alice", "data2_admin"}});

                TestGetFilteredGroupingPolicy(e, 0, std::vector<std::vector<std::string>>{{"alice", "data2_admin"}}, std::vector<std::string>{"alice"});
                TestGetFilteredGroupingPolicy(e, 0, std::vector<std::vector<std::string>>{}, std::vector<std::string>{"bob"});
                TestGetFilteredGroupingPolicy(e, 1, std::vector<std::vector<std::string>>{}, std::vector<std::string>{"data1_admin"});
                TestGetFilteredGroupingPolicy(e, 1, std::vector<std::vector<std::string>>{ {"alice", "data2_admin"}}, std::vector<std::string>{"data2_admin"});
                // Note: "" (empty string) in fieldValues means matching all values.
                TestGetFilteredGroupingPolicy(e, 0, std::vector<std::vector<std::string>>{ {"alice", "data2_admin"}}, std::vector<std::string>{"", "data2_admin"});

                TestHasGroupingPolicy(e, std::vector<std::string>{"alice", "data2_admin"}, true);
                TestHasGroupingPolicy(e, std::vector<std::string>{"bob", "data2_admin"}, false);
            }


            TEST_METHOD(TestModifyPolicyAPI) {
                std::string model = "../../examples/rbac_model.conf";
                std::string policy = "../../examples/rbac_policy.csv";
                std::shared_ptr<Adapter> adapter = std::shared_ptr<Adapter>(new BatchFileAdapter(policy));
                Enforcer e = Enforcer(model, adapter);

                TestGetPolicy(e, std::vector<std::vector<std::string>>{
                    {"alice", "data1", "read"},
                    { "bob", "data2", "write" },
                    { "data2_admin", "data2", "read" },
                    { "data2_admin", "data2", "write" }});

                e.RemovePolicy(std::vector<std::string>{"alice", "data1", "read"});
                e.RemovePolicy(std::vector<std::string>{"bob", "data2", "write"});
                e.RemovePolicy(std::vector<std::string>{"alice", "data1", "read"});
                e.AddPolicy(std::vector<std::string>{"eve", "data3", "read"});
                e.AddPolicy(std::vector<std::string>{"eve", "data3", "read"});

                std::vector<std::vector<std::string>>rules{
                    {"jack", "data4", "read"},
                    {"katy", "data4", "write"},
                    {"leyo", "data4", "read"},
                    {"ham", "data4", "write"},
                };

                e.AddPolicies(rules);
                e.AddPolicies(rules);

                TestGetPolicy(e, std::vector<std::vector<std::string>>{
                    {"data2_admin", "data2", "read"},
                    { "data2_admin", "data2", "write" },
                    { "eve", "data3", "read" },
                    { "jack", "data4", "read" },
                    { "katy", "data4", "write" },
                    { "leyo", "data4", "read" },
                    { "ham", "data4", "write" }});

                e.RemovePolicies(rules);
                e.RemovePolicies(rules);

                std::vector<std::string>named_policy{ "eve", "data3", "read" };
                e.RemoveNamedPolicy("p", named_policy);
                e.AddNamedPolicy("p", named_policy);

                TestGetPolicy(e, std::vector<std::vector<std::string>>{
                    {"data2_admin", "data2", "read"},
                    { "data2_admin", "data2", "write" },
                    { "eve", "data3", "read" }});

                e.RemoveFilteredPolicy(1, std::vector<std::string>{"data2"});

                TestGetPolicy(e, std::vector<std::vector<std::string>>{ {"eve", "data3", "read"}});
            }

            TEST_METHOD(TestModifyGroupingPolicyAPI) {
                std::string model = "../../examples/rbac_model.conf";
                std::string policy = "../../examples/rbac_policy.csv";
                std::shared_ptr<Adapter> adapter = std::shared_ptr<Adapter>(new BatchFileAdapter(policy));
                Enforcer e = Enforcer(model, adapter);

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"data2_admin"}, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{}, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{}, e.GetRolesForUser("eve")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{}, e.GetRolesForUser("non_exist")));

                e.RemoveGroupingPolicy(std::vector<std::string>{"alice", "data2_admin"});
                e.AddGroupingPolicy(std::vector<std::string>{"bob", "data1_admin"});
                e.AddGroupingPolicy(std::vector<std::string>{"eve", "data3_admin"});

                std::vector<std::vector<std::string>> grouping_rules{
                    {"ham", "data4_admin"},
                    {"jack", "data5_admin"},
                };

                e.AddGroupingPolicies(grouping_rules);
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"data4_admin"}, e.GetRolesForUser("ham")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"data5_admin"}, e.GetRolesForUser("jack")));
                e.RemoveGroupingPolicies(grouping_rules);

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{}, e.GetRolesForUser("alice")));
                std::vector<std::string> named_grouping_policy{ "alice", "data2_admin" };
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{}, e.GetRolesForUser("alice")));
                e.AddNamedGroupingPolicy("g", named_grouping_policy);
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"data2_admin"}, e.GetRolesForUser("alice")));
                e.RemoveNamedGroupingPolicy("g", named_grouping_policy);

                e.AddNamedGroupingPolicies("g", grouping_rules);
                e.AddNamedGroupingPolicies("g", grouping_rules);
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"data4_admin"}, e.GetRolesForUser("ham")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"data5_admin"}, e.GetRolesForUser("jack")));
                e.RemoveNamedGroupingPolicies("g", grouping_rules);
                e.RemoveNamedGroupingPolicies("g", grouping_rules);

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{}, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"data1_admin"}, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"data3_admin"}, e.GetRolesForUser("eve")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{}, e.GetRolesForUser("non_exist")));

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"bob"}, e.GetUsersForRole("data1_admin")));
                try {
                    e.GetUsersForRole("data2_admin", std::vector<std::string>{});
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"eve"}, e.GetUsersForRole("data3_admin")));
                
                e.RemoveFilteredGroupingPolicy(0, std::vector<std::string>{"bob"});

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{}, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{}, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"data3_admin"}, e.GetRolesForUser("eve")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{}, e.GetRolesForUser("non_exist")));

                try {
                    e.GetUsersForRole("data1_admin");
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                try {
                    e.GetUsersForRole("data2_admin");
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{"eve"}, e.GetUsersForRole("data3_admin")));
            }
    };
}

#endif // TEST_MANAGEMENT_API_CPP
