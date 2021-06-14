#include <gtest/gtest.h>
#include <casbin/casbin.h>

TEST(TestEnforcer, TestFourParams) {
    std::string model = "../../examples/rbac_with_domains_model.conf";
    std::string policy = "../../examples/rbac_with_domains_policy.csv";
    casbin::Enforcer e = casbin::Enforcer(model, policy);

    ASSERT_EQ(e.Enforce({ "alice", "domain1", "data1", "read" }), true);
    ASSERT_EQ(e.Enforce({ "alice", "domain1", "data1", "write" }), true);
    ASSERT_EQ(e.Enforce({ "alice", "domain1", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "domain1", "data2", "write" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "domain2", "data1", "read" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "domain2", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "domain2", "data2", "read" }), true);
    ASSERT_EQ(e.Enforce({ "bob", "domain2", "data2", "write" }), true);
}

TEST(TestEnforcer, TestThreeParams) {
    std::string model = "../../examples/basic_model_without_spaces.conf";
    std::string policy = "../../examples/basic_policy.csv";
    casbin::Enforcer e(model, policy);

    ASSERT_EQ(e.Enforce({ "alice", "data1", "read" }), true);
    ASSERT_EQ(e.Enforce({ "alice", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "write" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data1", "read" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data2", "write" }), true);
}
