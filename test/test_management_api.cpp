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

                Assert::IsTrue(ArrayEquals({ "alice", "bob", "data2_admin" }, e.GetAllSubjects()));
                Assert::IsTrue(ArrayEquals({ "data1", "data2" }, e.GetAllObjects()));
                Assert::IsTrue(ArrayEquals({ "read", "write" }, e.GetAllActions()));
                Assert::IsTrue(ArrayEquals({ "data2_admin" }, e.GetAllRoles()));
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


            TEST_METHOD(TestModifyPolicyAPI) {
                std::string model = "../../examples/rbac_model.conf";
                std::string policy = "../../examples/rbac_policy.csv";
                std::shared_ptr<Adapter> adapter = std::shared_ptr<Adapter>(new BatchFileAdapter(policy));
                Enforcer e = Enforcer(model, adapter);

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

            TEST_METHOD(TestModifyGroupingPolicyAPI) {
                std::string model = "../../examples/rbac_model.conf";
                std::string policy = "../../examples/rbac_policy.csv";
                std::shared_ptr<Adapter> adapter = std::make_shared<BatchFileAdapter>(policy);
                Enforcer e = Enforcer(model, adapter);

                Assert::IsTrue(ArrayEquals({"data2_admin"}, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals({}, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals({}, e.GetRolesForUser("eve")));
                Assert::IsTrue(ArrayEquals({}, e.GetRolesForUser("non_exist")));

                e.RemoveGroupingPolicy({"alice", "data2_admin"});
                e.AddGroupingPolicy({"bob", "data1_admin"});
                e.AddGroupingPolicy({"eve", "data3_admin"});

                std::vector<std::vector<std::string>> grouping_rules {
                    {"ham", "data4_admin"},
                    {"jack", "data5_admin"},
                };

                e.AddGroupingPolicies(grouping_rules);
                Assert::IsTrue(ArrayEquals({"data4_admin"}, e.GetRolesForUser("ham")));
                Assert::IsTrue(ArrayEquals({"data5_admin"}, e.GetRolesForUser("jack")));
                e.RemoveGroupingPolicies(grouping_rules);

                Assert::IsTrue(ArrayEquals({}, e.GetRolesForUser("alice")));
                std::vector<std::string> named_grouping_policy{ "alice", "data2_admin" };
                Assert::IsTrue(ArrayEquals({}, e.GetRolesForUser("alice")));
                e.AddNamedGroupingPolicy("g", named_grouping_policy);
                Assert::IsTrue(ArrayEquals({"data2_admin"}, e.GetRolesForUser("alice")));
                e.RemoveNamedGroupingPolicy("g", named_grouping_policy);

                e.AddNamedGroupingPolicies("g", grouping_rules);
                e.AddNamedGroupingPolicies("g", grouping_rules);
                Assert::IsTrue(ArrayEquals({"data4_admin"}, e.GetRolesForUser("ham")));
                Assert::IsTrue(ArrayEquals({"data5_admin"}, e.GetRolesForUser("jack")));
                e.RemoveNamedGroupingPolicies("g", grouping_rules);
                e.RemoveNamedGroupingPolicies("g", grouping_rules);

                Assert::IsTrue(ArrayEquals({}, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals({"data1_admin"}, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals({"data3_admin"}, e.GetRolesForUser("eve")));
                Assert::IsTrue(ArrayEquals({}, e.GetRolesForUser("non_exist")));

                Assert::IsTrue(ArrayEquals({"bob"}, e.GetUsersForRole("data1_admin")));
                try {
                    e.GetUsersForRole("data2_admin", {});
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                Assert::IsTrue(ArrayEquals({"eve"}, e.GetUsersForRole("data3_admin")));
                
                e.RemoveFilteredGroupingPolicy(0, {"bob"});

                Assert::IsTrue(ArrayEquals({}, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals({}, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals({"data3_admin"}, e.GetRolesForUser("eve")));
                Assert::IsTrue(ArrayEquals({}, e.GetRolesForUser("non_exist")));

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
                Assert::IsTrue(ArrayEquals({"eve"}, e.GetUsersForRole("data3_admin")));

                Assert::IsTrue(e.AddGroupingPolicy({"data3_admin", "data4_admin"}));
                e.UpdateGroupingPolicy({"eve", "data3_admin"}, {"eve", "admin"});
                e.UpdateGroupingPolicy({"data3_admin", "data4_admin"}, {"admin", "data4_admin"});

                // Assert::IsTrue(ArrayEquals({"admin"}, e.GetUsersForRole("data4_admin")));
                Assert::IsTrue(ArrayEquals({"eve"}, e.GetUsersForRole("admin")));

                Assert::IsTrue(ArrayEquals({"admin"}, e.GetRolesForUser("eve")));
                Assert::IsTrue(ArrayEquals({"data4_admin"}, e.GetRolesForUser("admin")));
            }
    };
}

#endif // TEST_MANAGEMENT_API_CPP
