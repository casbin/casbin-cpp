#pragma once

#include "pch.h"

#include <rbac.h>

using namespace std;

namespace test_role_manager
{
    TEST_CLASS(TestRoleManager)
    {
        public:

            void TestRole(RoleManager* rm, string name1, string name2, bool res) {
                bool my_res = rm->HasLink(name1, name2);

                Assert::AreEqual(res, my_res);
            }

            void TestDomainRole(RoleManager* rm, string name1, string name2, vector<string> domain, bool res) {
                bool my_res = rm->HasLink(name1, name2, domain);

                Assert::AreEqual(res, my_res);
            }

            TEST_METHOD(TestRole) {
                RoleManager* rm = DefaultRoleManager :: NewRoleManager(3);
                rm->AddLink("u1", "g1");
                rm->AddLink("u2", "g1");
                rm->AddLink("u3", "g2");
                rm->AddLink("u4", "g2");
                rm->AddLink("u4", "g3");
                rm->AddLink("g1", "g3");

                // Current role inheritance tree:
                //             g3    g2
                //            /  \  /  \
                //          g1    u4    u3
                //         /  \
                //       u1    u2

                TestRole(rm, "u1", "g1", true);
                TestRole(rm, "u1", "g2", false);
                TestRole(rm, "u1", "g3", true);
                TestRole(rm, "u2", "g1", true);
                TestRole(rm, "u2", "g2", false);
                TestRole(rm, "u2", "g3", true);
                TestRole(rm, "u3", "g1", false);
                TestRole(rm, "u3", "g2", true);
                TestRole(rm, "u3", "g3", false);
                TestRole(rm, "u4", "g1", false);
                TestRole(rm, "u4", "g2", true);
                TestRole(rm, "u4", "g3", true);

                rm->DeleteLink("g1", "g3");
                rm->DeleteLink("u4", "g2");

                // Current role inheritance tree after deleting the links:
                //             g3    g2
                //               \     \
                //          g1    u4    u3
                //         /  \
                //       u1    u2

                TestRole(rm, "u1", "g1", true);
                TestRole(rm, "u1", "g2", false);
                TestRole(rm, "u1", "g3", false);
                TestRole(rm, "u2", "g1", true);
                TestRole(rm, "u2", "g2", false);
                TestRole(rm, "u2", "g3", false);
                TestRole(rm, "u3", "g1", false);
                TestRole(rm, "u3", "g2", true);
                TestRole(rm, "u3", "g3", false);
                TestRole(rm, "u4", "g1", false);
                TestRole(rm, "u4", "g2", false);
                TestRole(rm, "u4", "g3", true);
            }

            TEST_METHOD(TestDomainRole) {
                RoleManager* rm = DefaultRoleManager :: NewRoleManager(3);
                vector<string> domain1{ "domain1" };
                vector<string> domain2{ "domain2" };
                rm->AddLink("u1", "g1", domain1);
                rm->AddLink("u2", "g1", domain1);
                rm->AddLink("u3", "admin", domain2);
                rm->AddLink("u4", "admin", domain2);
                rm->AddLink("u4", "admin", domain1);
                rm->AddLink("g1", "admin", domain1);

                // Current role inheritance tree:
                //       domain1:admin    domain2:admin
                //            /       \  /       \
                //      domain1:g1     u4         u3
                //         /  \
                //       u1    u2

                TestDomainRole(rm, "u1", "g1", domain1, true);
                TestDomainRole(rm, "u1", "g1", domain2, false);
                TestDomainRole(rm, "u1", "admin", domain1, true);
                TestDomainRole(rm, "u1", "admin", domain2, false);

                TestDomainRole(rm, "u2", "g1", domain1, true);
                TestDomainRole(rm, "u2", "g1", domain2, false);
                TestDomainRole(rm, "u2", "admin", domain1, true);
                TestDomainRole(rm, "u2", "admin", domain2, false);

                TestDomainRole(rm, "u3", "g1", domain1, false);
                TestDomainRole(rm, "u3", "g1", domain2, false);
                TestDomainRole(rm, "u3", "admin", domain1, false);
                TestDomainRole(rm, "u3", "admin", domain2, true);

                TestDomainRole(rm, "u4", "g1", domain1, false);
                TestDomainRole(rm, "u4", "g1", domain2, false);
                TestDomainRole(rm, "u4", "admin", domain1, true);
                TestDomainRole(rm, "u4", "admin", domain2, true);

                rm->DeleteLink("g1", "admin", domain1);
                rm->DeleteLink("u4", "admin", domain2);

                // Current role inheritance tree after deleting the links:
                //       domain1:admin    domain2:admin
                //                    \          \
                //      domain1:g1     u4         u3
                //         /  \
                //       u1    u2

                TestDomainRole(rm, "u1", "g1", domain1, true);
                TestDomainRole(rm, "u1", "g1", domain2, false);
                TestDomainRole(rm, "u1", "admin", domain1, false);
                TestDomainRole(rm, "u1", "admin", domain2, false);

                TestDomainRole(rm, "u2", "g1", domain1, true);
                TestDomainRole(rm, "u2", "g1", domain2, false);
                TestDomainRole(rm, "u2", "admin", domain1, false);
                TestDomainRole(rm, "u2", "admin", domain2, false);

                TestDomainRole(rm, "u3", "g1", domain1, false);
                TestDomainRole(rm, "u3", "g1", domain2, false);
                TestDomainRole(rm, "u3", "admin", domain1, false);
                TestDomainRole(rm, "u3", "admin", domain2, true);

                TestDomainRole(rm, "u4", "g1", domain1, false);
                TestDomainRole(rm, "u4", "g1", domain2, false);
                TestDomainRole(rm, "u4", "admin", domain1, true);
                TestDomainRole(rm, "u4", "admin", domain2, false);
            }

            TEST_METHOD(TestClear) {
                RoleManager* rm = DefaultRoleManager::NewRoleManager(3);
                rm->AddLink("u1", "g1");
                rm->AddLink("u2", "g1");
                rm->AddLink("u3", "g2");
                rm->AddLink("u4", "g2");
                rm->AddLink("u4", "g3");
                rm->AddLink("g1", "g3");

                // Current role inheritance tree:
                //             g3    g2
                //            /  \  /  \
                //          g1    u4    u3
                //         /  \
                //       u1    u2

                rm->Clear();

                // All data is cleared.
                // No role inheritance now.

                TestRole(rm, "u1", "g1", false);
                TestRole(rm, "u1", "g2", false);
                TestRole(rm, "u1", "g3", false);
                TestRole(rm, "u2", "g1", false);
                TestRole(rm, "u2", "g2", false);
                TestRole(rm, "u2", "g3", false);
                TestRole(rm, "u3", "g1", false);
                TestRole(rm, "u3", "g2", false);
                TestRole(rm, "u3", "g3", false);
                TestRole(rm, "u4", "g1", false);
                TestRole(rm, "u4", "g2", false);
                TestRole(rm, "u4", "g3", false);
            }
    };
}