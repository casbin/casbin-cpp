#include "pch.h"

#ifndef TEST_RBAC_API_CPP
#define TEST_RBAC_API_CPP


#include <enforcer.h>
#include <rbac.h>
#include <util.h>

namespace test_rbac_api
{
    using namespace casbin;

    TEST_CLASS(TestRBACAPI)
    {
        public:

            TEST_METHOD(TestRoleAPI) {
                Enforcer e = Enforcer("../../examples/rbac_model.conf", "../../examples/rbac_policy.csv");

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "data2_admin" }, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("data2_admin")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("non_exist")));

                Assert::IsFalse(e.HasRoleForUser("alice", "data1_admin"));
                Assert::IsTrue(e.HasRoleForUser("alice", "data2_admin"));

                e.AddRoleForUser("alice", "data1_admin");

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "data1_admin", "data2_admin" }, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("data2_admin")));

                e.DeleteRoleForUser("alice", "data1_admin");

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "data2_admin" }, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("data2_admin")));

                e.DeleteRolesForUser("alice");

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("data2_admin")));

                e.AddRoleForUser("alice", "data1_admin");
                e.DeleteUser("alice");

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetRolesForUser("data2_admin")));

                e.AddRoleForUser("alice", "data2_admin");

                Assert::IsFalse(e.Enforce({ "alice", "data1", "read" }));
                Assert::IsFalse(e.Enforce({ "alice", "data1", "write" }));
                Assert::IsTrue(e.Enforce({ "alice", "data2", "read" }));
                Assert::IsTrue(e.Enforce({ "alice", "data2", "write" }));
                Assert::IsFalse(e.Enforce({ "bob", "data1", "read" }));
                Assert::IsFalse(e.Enforce({ "bob", "data1", "write" }));
                Assert::IsFalse(e.Enforce({ "bob", "data2", "read" }));
                Assert::IsTrue(e.Enforce({ "bob", "data2", "write" }));

                e.DeleteRole("data2_admin");

                Assert::IsFalse(e.Enforce({ "alice", "data1", "read" }));
                Assert::IsFalse(e.Enforce({ "alice", "data1", "write" }));
                Assert::IsFalse(e.Enforce({ "alice", "data2", "read" }));
                Assert::IsFalse(e.Enforce({ "alice", "data2", "write" }));
                Assert::IsFalse(e.Enforce({ "bob", "data1", "read" }));
                Assert::IsFalse(e.Enforce({ "bob", "data1", "write" }));
                Assert::IsFalse(e.Enforce({ "bob", "data2", "read" }));
                Assert::IsTrue(e.Enforce({ "bob", "data2", "write" }));
            }

            TEST_METHOD(TestEnforcer_AddRolesForUser) {
                Enforcer e = Enforcer("../../examples/rbac_model.conf", "../../examples/rbac_policy.csv");

                e.AddRolesForUser("alice", std::vector<std::string>{ "data1_admin", "data2_admin", "data3_admin" });
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "data1_admin", "data2_admin", "data3_admin" }, e.GetRolesForUser("alice")));

                Assert::IsTrue(e.Enforce({ "alice", "data1", "read" }));
                Assert::IsTrue(e.Enforce({ "alice", "data2", "read" }));
                Assert::IsTrue(e.Enforce({ "alice", "data2", "write" }));
            }

            void TestGetPermissions(Enforcer e, std::string name, std::vector<std::vector<std::string>> res) {
                std::vector<std::vector<std::string>> my_res = e.GetPermissionsForUser(name);

                int count = 0;
                for (int i = 0; i < my_res.size(); i++) {
                    for (int j = 0; j < res.size(); j++) {
                        if (ArrayEquals(res[j], my_res[i])) {
                            count += 1;
                            break;
                        }
                    }
                }

                Assert::AreEqual(int(res.size()), count);
            }

            TEST_METHOD(TestPermissionAPI) {
                Enforcer e = Enforcer("../../examples/basic_without_resources_model.conf", "../../examples/basic_without_resources_policy.csv");

                Assert::IsTrue(e.Enforce(std::vector<std::string>{ "alice", "read" }));
                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "alice", "write" }));
                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "bob", "read" }));
                Assert::IsTrue(e.Enforce(std::vector<std::string>{ "bob", "write" }));

                TestGetPermissions(e, "alice", std::vector<std::vector<std::string>>{ {"alice", "read"} });
                TestGetPermissions(e, "bob", std::vector<std::vector<std::string>>{ {"bob", "write"} });

                Assert::IsTrue(e.HasPermissionForUser("alice", { "read" }));
                Assert::IsFalse(e.HasPermissionForUser("alice", { "write" }));
                Assert::IsFalse(e.HasPermissionForUser("bob", { "read" }));
                Assert::IsTrue(e.HasPermissionForUser("bob", { "write" }));

                e.DeletePermission({ "read" });

                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "alice", "read" }));
                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "alice", "write" }));
                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "bob", "read" }));
                Assert::IsTrue(e.Enforce(std::vector<std::string>{ "bob", "write" }));

                e.AddPermissionForUser("bob", { "read" });

                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "alice", "read" }));
                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "alice", "write" }));
                Assert::IsTrue(e.Enforce(std::vector<std::string>{ "bob", "read" }));
                Assert::IsTrue(e.Enforce(std::vector<std::string>{ "bob", "write" }));

                e.DeletePermissionForUser("bob", { "read" });

                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "alice", "read" }));
                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "alice", "write" }));
                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "bob", "read" }));
                Assert::IsTrue(e.Enforce(std::vector<std::string>{ "bob", "write" }));

                e.DeletePermissionsForUser("bob");

                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "alice", "read" }));
                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "alice", "write" }));
                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "bob", "read" }));
                Assert::IsFalse(e.Enforce(std::vector<std::string>{ "bob", "write" }));
            }

            TEST_METHOD(TestImplicitRoleAPI) {
                Enforcer e = Enforcer("../../examples/rbac_model.conf", "../../examples/rbac_with_hierarchy_policy.csv");

                TestGetPermissions(e, "alice", std::vector<std::vector<std::string>>{ {"alice", "data1", "read"} });
                TestGetPermissions(e, "bob", std::vector<std::vector<std::string>>{ {"bob", "data2", "write"} });

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "admin", "data1_admin", "data2_admin" }, e.GetImplicitRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ }, e.GetImplicitRolesForUser("bob")));

                e = Enforcer("../../examples/rbac_with_pattern_model.conf", "../../examples/rbac_with_pattern_policy.csv");

                dynamic_cast<DefaultRoleManager*>(e.GetRoleManager().get())->AddMatchingFunc(KeyMatch);

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "/book/1/2/3/4/5", "pen_admin", "/book/*", "book_group" }, e.GetImplicitRolesForUser("cathy")));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "/book/1/2/3/4/5", "pen_admin" }, e.GetRolesForUser("cathy")));
            }

            void TestGetImplicitPermissions(Enforcer e, std::string name, std::vector<std::vector<std::string>> res) {
                std::vector<std::vector<std::string>> my_res = e.GetImplicitPermissionsForUser(name);

                int count = 0;
                for (int i = 0; i < my_res.size(); i++) {
                    for (int j = 0; j < res.size(); j++) {
                        if (ArrayEquals(res[j], my_res[i])) {
                            count += 1;
                            break;
                        }
                    }
                }

                Assert::AreEqual(int(res.size()), count);
            }

            void TestGetImplicitPermissionsWithDomain(Enforcer e, std::string name, std::string domain, std::vector<std::vector<std::string>> res) {
                std::vector<std::vector<std::string>> my_res = e.GetImplicitPermissionsForUser(name, { domain });
                
                int count = 0;
                for (int i = 0; i < my_res.size(); i++) {
                    for (int j = 0; j < res.size(); j++) {
                        if (ArrayEquals(res[j], my_res[i])) {
                            count += 1;
                            break;
                        }
                    }
                }

                Assert::AreEqual(int(res.size()), count);
            }

            TEST_METHOD(TestImplicitPermissionAPI) {
                Enforcer e = Enforcer("../../examples/rbac_model.conf", "../../examples/rbac_with_hierarchy_policy.csv");

                TestGetPermissions(e, "alice", std::vector<std::vector<std::string>>{ {"alice", "data1", "read"} });
                TestGetPermissions(e, "bob", std::vector<std::vector<std::string>>{ {"bob", "data2", "write"} });

                TestGetImplicitPermissions(e, "alice", std::vector<std::vector<std::string>>{ {"alice", "data1", "read"}, { "data1_admin", "data1", "read" }, { "data1_admin", "data1", "write" }, { "data2_admin", "data2", "read" }, { "data2_admin", "data2", "write" } });
                TestGetImplicitPermissions(e, "bob", std::vector<std::vector<std::string>>{ {"bob", "data2", "write"} });
            }

            TEST_METHOD(TestImplicitPermissionAPIWithDomain) {
                Enforcer e = Enforcer("../../examples/rbac_with_domains_model.conf", "../../examples/rbac_with_hierarchy_with_domains_policy.csv");
                TestGetImplicitPermissionsWithDomain(e, "alice", "domain1", std::vector<std::vector<std::string>>{ {"alice", "domain1", "data2", "read"}, { "role:reader", "domain1", "data1", "read" }, { "role:writer", "domain1", "data1", "write" } });
            }

            TEST_METHOD(TestImplicitUserAPI) {
                Enforcer e = Enforcer("../../examples/rbac_model.conf", "../../examples/rbac_with_hierarchy_policy.csv");

                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "alice" }, e.GetImplicitUsersForPermission({ "data1", "read" })));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "alice" }, e.GetImplicitUsersForPermission({ "data1", "write" })));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "alice" }, e.GetImplicitUsersForPermission({ "data2", "read" })));
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "alice", "bob" }, e.GetImplicitUsersForPermission({ "data2", "write" })));

                e.ClearPolicy();
                e.AddPolicy({ "admin", "data1", "read" });
                e.AddPolicy({ "bob", "data1", "read" });
                e.AddGroupingPolicy({ "alice", "admin" });
                Assert::IsTrue(ArrayEquals(std::vector<std::string>{ "alice", "bob" }, e.GetImplicitUsersForPermission({ "data1", "read" })));
            }
    };
}

#endif // TEST_RBAC_API_CPP
