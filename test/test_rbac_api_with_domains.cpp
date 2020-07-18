#pragma once

#include "pch.h"

#include <enforcer.h>
#include <exception.h>
#include <rbac.h>
#include <util.h>

using namespace std;

namespace test_rbac_api_with_domains
{
    TEST_CLASS(TestRBACAPIWithDomains)
    {
        public:

            TEST_METHOD(TestGetImplicitRolesForDomainUser) {
                unique_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/rbac_with_domains_model.conf", "../../examples/rbac_with_hierarchy_with_domains_policy.csv");

                // This is only able to retrieve the first level of roles.
                Assert::IsTrue(ArrayEquals({ "role:global_admin" }, e->GetRolesForUserInDomain("alice", { "domain1" })));

                // Retrieve all inherit roles. It supports domains as well.
                Assert::IsTrue(ArrayEquals(vector<string>{"role:global_admin", "role:reader", "role:writer"}, e->GetImplicitRolesForUser("alice", {"domain1"})));
            }

            // TestUserAPIWithDomains: Add by Gordon
            TEST_METHOD(TestUserAPIWithDomains) {
                unique_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/rbac_with_domains_model.conf", "../../examples/rbac_with_domains_policy.csv");

                Assert::IsTrue(ArrayEquals({ "alice" }, e->GetUsersForRole("admin", { "domain1" })));
                Assert::IsTrue(ArrayEquals({ "alice" }, e->GetUsersForRoleInDomain("admin", { "domain1" })));
                
                try {
                    e->GetUsersForRole("non_exist", { "domain1" });
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                try {
                    e->GetUsersForRoleInDomain("non_exist", { "domain1" });
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }

                Assert::IsTrue(ArrayEquals({ "bob" }, e->GetUsersForRole("admin", { "domain2" })));
                Assert::IsTrue(ArrayEquals({ "bob" }, e->GetUsersForRoleInDomain("admin", { "domain2" })));

                try {
                    e->GetUsersForRole("non_exist", { "domain2" });
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                try {
                    e->GetUsersForRoleInDomain("non_exist", { "domain2" });
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }

                e->DeleteRoleForUserInDomain("alice", "admin", "domain1");
                e->AddRoleForUserInDomain("bob", "admin", "domain1");

                Assert::IsTrue(ArrayEquals({ "bob" }, e->GetUsersForRole("admin", { "domain1" })));
                Assert::IsTrue(ArrayEquals({ "bob" }, e->GetUsersForRoleInDomain("admin", { "domain1" })));

                try {
                    e->GetUsersForRole("non_exist", { "domain1" });
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                try {
                    e->GetUsersForRoleInDomain("non_exist", { "domain1" });
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }

                Assert::IsTrue(ArrayEquals({ "bob" }, e->GetUsersForRole("admin", { "domain2" })));
                Assert::IsTrue(ArrayEquals({ "bob" }, e->GetUsersForRoleInDomain("admin", { "domain2" })));

                try {
                    e->GetUsersForRole("non_exist", { "domain2" });
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
                try {
                    e->GetUsersForRoleInDomain("non_exist", { "domain2" });
                }
                catch (CasbinRBACException e) {
                    Assert::IsTrue(true);
                }
            }

            TEST_METHOD(TestRoleAPIWithDomains) {
                unique_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/rbac_with_domains_model.conf", "../../examples/rbac_with_domains_policy.csv");
                
                Assert::IsTrue(ArrayEquals({ "admin" }, e->GetRolesForUser("alice", { "domain1" })));
                Assert::IsTrue(ArrayEquals({ "admin" }, e->GetRolesForUserInDomain("alice", { "domain1" })));

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("bob", { "domain1" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("bob", { "domain1" })));

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("admin", { "domain1" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("admin", { "domain1" })));
                
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("non_exist", { "domain1" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("non_exist", { "domain1" })));

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("alice", { "domain2" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("alice", { "domain2" })));

                Assert::IsTrue(ArrayEquals({ "admin" }, e->GetRolesForUser("bob", { "domain2" })));
                Assert::IsTrue(ArrayEquals({ "admin" }, e->GetRolesForUserInDomain("bob", { "domain2" })));

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("admin", { "domain2" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("admin", { "domain2" })));

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("non_exist", { "domain2" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("non_exist", { "domain2" })));

                e->DeleteRoleForUserInDomain("alice", "admin", "domain1");
                e->AddRoleForUserInDomain("bob", "admin", "domain1");

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("alice", { "domain1" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("alice", { "domain1" })));

                Assert::IsTrue(ArrayEquals({ "admin" }, e->GetRolesForUser("bob", { "domain1" })));
                Assert::IsTrue(ArrayEquals({ "admin" }, e->GetRolesForUserInDomain("bob", { "domain1" })));

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("admin", { "domain1" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("admin", { "domain1" })));

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("non_exist", { "domain1" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("non_exist", { "domain1" })));

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("alice", { "domain2" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("alice", { "domain2" })));

                Assert::IsTrue(ArrayEquals({ "admin" }, e->GetRolesForUser("bob", { "domain2" })));
                Assert::IsTrue(ArrayEquals({ "admin" }, e->GetRolesForUserInDomain("bob", { "domain2" })));

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("admin", { "domain2" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("admin", { "domain2" })));

                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUser("non_exist", { "domain2" })));
                Assert::IsTrue(ArrayEquals({ }, e->GetRolesForUserInDomain("non_exist", { "domain2" })));
            }

            void TestGetPermissionsInDomain(unique_ptr<Enforcer>& e, string name, string domain, vector<vector<string>> res) {
                vector<vector<string>> my_res = e->GetPermissionsForUserInDomain(name, { domain });

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

            TEST_METHOD(TestPermissionAPIInDomain) {
                unique_ptr<Enforcer> e = Enforcer::NewEnforcer("../../examples/rbac_with_domains_model.conf", "../../examples/rbac_with_domains_policy.csv");

                TestGetPermissionsInDomain(e, "alice", "domain1", {});
                TestGetPermissionsInDomain(e, "bob", "domain1", {});
                TestGetPermissionsInDomain(e, "admin", "domain1", { {"admin", "domain1", "data1", "read"}, {"admin", "domain1", "data1", "write"} });
                TestGetPermissionsInDomain(e, "non_exist", "domain1", {});

                TestGetPermissionsInDomain(e, "alice", "domain2", {});
                TestGetPermissionsInDomain(e, "bob", "domain2", {});
                TestGetPermissionsInDomain(e, "admin", "domain2", { {"admin", "domain2", "data2", "read"}, {"admin", "domain2", "data2", "write"} });
                TestGetPermissionsInDomain(e, "non_exist", "domain2", {});
            }
    };
}