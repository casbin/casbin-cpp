#pragma once

#include "pch.h"

#include <enforcer.h>
#include <rbac.h>
#include <util.h>

using namespace std;

namespace test_rbac_api
{
    TEST_CLASS(TestRBACAPI)
    {
        public:

            TEST_METHOD(TestRoleAPI) {
                shared_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/rbac_model.conf", "../../examples/rbac_policy.csv");

                Assert::IsTrue(ArrayEquals(vector<string>{ "data2_admin" }, e->GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("data2_admin")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("non_exist")));

                Assert::IsFalse(e->HasRoleForUser("alice", "data1_admin"));
                Assert::IsTrue(e->HasRoleForUser("alice", "data2_admin"));

                e->AddRoleForUser("alice", "data1_admin");

                Assert::IsTrue(ArrayEquals(vector<string>{ "data1_admin", "data2_admin" }, e->GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("data2_admin")));

                e->DeleteRoleForUser("alice", "data1_admin");

                Assert::IsTrue(ArrayEquals(vector<string>{ "data2_admin" }, e->GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("data2_admin")));

                e->DeleteRolesForUser("alice");

                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("data2_admin")));

                e->AddRoleForUser("alice", "data1_admin");
                e->DeleteUser("alice");

                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("bob")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetRolesForUser("data2_admin")));

                e->AddRoleForUser("alice", "data2_admin");

                Assert::IsFalse(e->Enforce({ "alice", "data1", "read" }));
                Assert::IsFalse(e->Enforce({ "alice", "data1", "write" }));
                Assert::IsTrue(e->Enforce({ "alice", "data2", "read" }));
                Assert::IsTrue(e->Enforce({ "alice", "data2", "write" }));
                Assert::IsFalse(e->Enforce({ "bob", "data1", "read" }));
                Assert::IsFalse(e->Enforce({ "bob", "data1", "write" }));
                Assert::IsFalse(e->Enforce({ "bob", "data2", "read" }));
                Assert::IsTrue(e->Enforce({ "bob", "data2", "write" }));

                e->DeleteRole("data2_admin");

                Assert::IsFalse(e->Enforce({ "alice", "data1", "read" }));
                Assert::IsFalse(e->Enforce({ "alice", "data1", "write" }));
                Assert::IsFalse(e->Enforce({ "alice", "data2", "read" }));
                Assert::IsFalse(e->Enforce({ "alice", "data2", "write" }));
                Assert::IsFalse(e->Enforce({ "bob", "data1", "read" }));
                Assert::IsFalse(e->Enforce({ "bob", "data1", "write" }));
                Assert::IsFalse(e->Enforce({ "bob", "data2", "read" }));
                Assert::IsTrue(e->Enforce({ "bob", "data2", "write" }));
            }

            TEST_METHOD(TestEnforcer_AddRolesForUser) {
                shared_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/rbac_model.conf", "../../examples/rbac_policy.csv");

                e->AddRolesForUser("alice", vector<string>{ "data1_admin", "data2_admin", "data3_admin" });
                Assert::IsTrue(ArrayEquals(vector<string>{ "data1_admin", "data2_admin", "data3_admin" }, e->GetRolesForUser("alice")));

                Assert::IsTrue(e->Enforce({ "alice", "data1", "read" }));
                Assert::IsTrue(e->Enforce({ "alice", "data2", "read" }));
                Assert::IsTrue(e->Enforce({ "alice", "data2", "write" }));
            }

            void TestGetPermissions(shared_ptr<Enforcer> e, string name, vector<vector<string>> res) {
                vector<vector<string>> my_res = e->GetPermissionsForUser(name);

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
                shared_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/basic_without_resources_model.conf", "../../examples/basic_without_resources_policy.csv");

                Assert::IsTrue(e->Enforce(vector<string>{ "alice", "read" }));
                Assert::IsFalse(e->Enforce(vector<string>{ "alice", "write" }));
                Assert::IsFalse(e->Enforce(vector<string>{ "bob", "read" }));
                Assert::IsTrue(e->Enforce(vector<string>{ "bob", "write" }));

                TestGetPermissions(e, "alice", vector<vector<string>>{ {"alice", "read"} });
                TestGetPermissions(e, "bob", vector<vector<string>>{ {"bob", "write"} });

                Assert::IsTrue(e->HasPermissionForUser("alice", { "read" }));
                Assert::IsFalse(e->HasPermissionForUser("alice", { "write" }));
                Assert::IsFalse(e->HasPermissionForUser("bob", { "read" }));
                Assert::IsTrue(e->HasPermissionForUser("bob", { "write" }));

                e->DeletePermission({ "read" });

                Assert::IsFalse(e->Enforce(vector<string>{ "alice", "read" }));
                Assert::IsFalse(e->Enforce(vector<string>{ "alice", "write" }));
                Assert::IsFalse(e->Enforce(vector<string>{ "bob", "read" }));
                Assert::IsTrue(e->Enforce(vector<string>{ "bob", "write" }));

                e->AddPermissionForUser("bob", { "read" });

                Assert::IsFalse(e->Enforce(vector<string>{ "alice", "read" }));
                Assert::IsFalse(e->Enforce(vector<string>{ "alice", "write" }));
                Assert::IsTrue(e->Enforce(vector<string>{ "bob", "read" }));
                Assert::IsTrue(e->Enforce(vector<string>{ "bob", "write" }));

                e->DeletePermissionForUser("bob", { "read" });

                Assert::IsFalse(e->Enforce(vector<string>{ "alice", "read" }));
                Assert::IsFalse(e->Enforce(vector<string>{ "alice", "write" }));
                Assert::IsFalse(e->Enforce(vector<string>{ "bob", "read" }));
                Assert::IsTrue(e->Enforce(vector<string>{ "bob", "write" }));

                e->DeletePermissionsForUser("bob");

                Assert::IsFalse(e->Enforce(vector<string>{ "alice", "read" }));
                Assert::IsFalse(e->Enforce(vector<string>{ "alice", "write" }));
                Assert::IsFalse(e->Enforce(vector<string>{ "bob", "read" }));
                Assert::IsFalse(e->Enforce(vector<string>{ "bob", "write" }));
            }

            TEST_METHOD(TestImplicitRoleAPI) {
                shared_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/rbac_model.conf", "../../examples/rbac_with_hierarchy_policy.csv");

                TestGetPermissions(e, "alice", vector<vector<string>>{ {"alice", "data1", "read"} });
                TestGetPermissions(e, "bob", vector<vector<string>>{ {"bob", "data2", "write"} });

                Assert::IsTrue(ArrayEquals(vector<string>{ "admin", "data1_admin", "data2_admin" }, e->GetImplicitRolesForUser("alice")));
                Assert::IsTrue(ArrayEquals(vector<string>{ }, e->GetImplicitRolesForUser("bob")));

                e = Enforcer::NewEnforcer("../../examples/rbac_with_pattern_model.conf", "../../examples/rbac_with_pattern_policy.csv");

                dynamic_cast<DefaultRoleManager*>(e->GetRoleManager().get())->AddMatchingFunc(KeyMatch);

                Assert::IsTrue(ArrayEquals(vector<string>{ "/book/1/2/3/4/5", "pen_admin", "/book/*", "book_group" }, e->GetImplicitRolesForUser("cathy")));
                Assert::IsTrue(ArrayEquals(vector<string>{ "/book/1/2/3/4/5", "pen_admin" }, e->GetRolesForUser("cathy")));
            }

            void TestGetImplicitPermissions(shared_ptr<Enforcer> e, string name, vector<vector<string>> res) {
                vector<vector<string>> my_res = e->GetImplicitPermissionsForUser(name);

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

            void TestGetImplicitPermissionsWithDomain(shared_ptr<Enforcer> e, string name, string domain, vector<vector<string>> res) {
                vector<vector<string>> my_res = e->GetImplicitPermissionsForUser(name, { domain });
                
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
                shared_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/rbac_model.conf", "../../examples/rbac_with_hierarchy_policy.csv");

                TestGetPermissions(e, "alice", vector<vector<string>>{ {"alice", "data1", "read"} });
                TestGetPermissions(e, "bob", vector<vector<string>>{ {"bob", "data2", "write"} });

                TestGetImplicitPermissions(e, "alice", vector<vector<string>>{ {"alice", "data1", "read"}, { "data1_admin", "data1", "read" }, { "data1_admin", "data1", "write" }, { "data2_admin", "data2", "read" }, { "data2_admin", "data2", "write" } });
                TestGetImplicitPermissions(e, "bob", vector<vector<string>>{ {"bob", "data2", "write"} });
            }

            TEST_METHOD(TestImplicitPermissionAPIWithDomain) {
                shared_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/rbac_with_domains_model.conf", "../../examples/rbac_with_hierarchy_with_domains_policy.csv");
                TestGetImplicitPermissionsWithDomain(e, "alice", "domain1", vector<vector<string>>{ {"alice", "domain1", "data2", "read"}, { "role:reader", "domain1", "data1", "read" }, { "role:writer", "domain1", "data1", "write" } });
            }

            TEST_METHOD(TestImplicitUserAPI) {
                shared_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/rbac_model.conf", "../../examples/rbac_with_hierarchy_policy.csv");

                Assert::IsTrue(ArrayEquals(vector<string>{ "alice" }, e->GetImplicitUsersForPermission({ "data1", "read" })));
                Assert::IsTrue(ArrayEquals(vector<string>{ "alice" }, e->GetImplicitUsersForPermission({ "data1", "write" })));
                Assert::IsTrue(ArrayEquals(vector<string>{ "alice" }, e->GetImplicitUsersForPermission({ "data2", "read" })));
                Assert::IsTrue(ArrayEquals(vector<string>{ "alice", "bob" }, e->GetImplicitUsersForPermission({ "data2", "write" })));

                e->ClearPolicy();
                e->AddPolicy({ "admin", "data1", "read" });
                e->AddPolicy({ "bob", "data1", "read" });
                e->AddGroupingPolicy({ "alice", "admin" });
                Assert::IsTrue(ArrayEquals(vector<string>{ "alice", "bob" }, e->GetImplicitUsersForPermission({ "data1", "read" })));
            }
    };
}