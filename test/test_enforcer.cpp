#include "pch.h"

#ifndef TEST_ENFORCER_CPP
#define TEST_ENFORCER_CPP


#include <enforcer.h>
#include <persist.h>
#include <rbac.h>
#include <util.h>

namespace test_enforcer
{
    using namespace casbin;

    TEST_CLASS(TestEnforcer)
    {
    public:

        void TestEnforce(Enforcer e, std::string sub, std::string dom, std::string obj, std::string act, bool res){
            Assert::AreEqual(res, e.Enforce({sub, dom, obj, act}));
        }

        void TestEnforce(Enforcer e, std::string sub, std::string obj, std::string act, bool res) {
            Assert::AreEqual(res, e.Enforce({sub, obj, act}));
        }

        void TestEnforce(Enforcer e, std::vector<std::string> params, bool res) {
            Assert::AreEqual(res, e.Enforce(params));
        }

        void TestEnforce(Enforcer e, std::unordered_map<std::string, std::string> params, bool res) {
            Assert::AreEqual(res, e.Enforce(params));
        }


        TEST_METHOD(TestFourParams) {

            std::string model = "../../examples/rbac_with_domains_model.conf";
            std::string policy = "../../examples/rbac_with_domains_policy.csv";
            Enforcer e = Enforcer(model, policy);

            TestEnforce(e, "alice", "domain1", "data1", "read", true);
            TestEnforce(e, "alice", "domain1", "data1", "write", true);
            TestEnforce(e, "alice", "domain1", "data2", "read", false);
            TestEnforce(e, "alice", "domain1", "data2", "write", false);
            TestEnforce(e, "bob", "domain2", "data1", "read", false);
            TestEnforce(e, "bob", "domain2", "data1", "write", false);
            TestEnforce(e, "bob", "domain2", "data2", "read", true);
            TestEnforce(e, "bob", "domain2", "data2", "write", true);
        }

        TEST_METHOD(TestThreeParams) {
            std::string model = "../../examples/basic_model_without_spaces.conf";
            std::string policy = "../../examples/basic_policy.csv";
            Enforcer e = Enforcer(model, policy);

            TestEnforce(e, { "alice", "data1", "read" }, true);
            TestEnforce(e, { "alice", "data1", "write" }, false);
            TestEnforce(e, { "alice", "data2", "read" }, false);
            TestEnforce(e, { "alice", "data2", "write" }, false);
            TestEnforce(e, { "bob", "data1", "read" }, false);
            TestEnforce(e, { "bob", "data1", "write" }, false);
            TestEnforce(e, { "bob", "data2", "read" }, false);
            TestEnforce(e, { "bob", "data2", "write" }, true);
        }
        
        TEST_METHOD(TestVectorParams) {
            std::string model = "../../examples/basic_model_without_spaces.conf";
            std::string policy = "../../examples/basic_policy.csv";
            Enforcer e = Enforcer(model, policy);

            TestEnforce(e, { "alice", "data1", "read" }, true);
            TestEnforce(e, { "alice", "data1", "write" }, false);
            TestEnforce(e, {"alice", "data2", "read" }, false);
            TestEnforce(e, {"alice", "data2", "write" }, false);
            TestEnforce(e, {"bob", "data1", "read" }, false);
            TestEnforce(e, {"bob", "data1", "write" }, false);
            TestEnforce(e, {"bob", "data2", "read" }, false);
            TestEnforce(e, {"bob", "data2", "write" }, true);
        }

        TEST_METHOD(TestMapParams) {
            std::string model = "../../examples/basic_model_without_spaces.conf";
            std::string policy = "../../examples/basic_policy.csv";
            Enforcer e = Enforcer(model, policy);

            std::unordered_map<std::string, std::string> params = {{"sub", "alice"}, {"obj", "data1"}, {"act", "read"}};
            TestEnforce(e, params, true);

            params = { {"sub","alice"},{"obj","data1"},{"act","write"} };
            TestEnforce(e, params, false);

            params = { {"sub","alice"},{"obj","data2"},{"act","read"} };
            TestEnforce(e, params, false);

            params = { {"sub","alice"},{"obj","data2"},{"act","write"} };
            TestEnforce(e, params, false);

            params = { {"sub","bob"},{"obj","data1"},{"act","read"} };
            TestEnforce(e, params, false);

            params = { {"sub","bob"},{"obj","data1"},{"act","write"} };
            TestEnforce(e, params, false);

            params = { {"sub","bob"},{"obj","data2"},{"act","read"} };
            TestEnforce(e, params, false);

            params = { {"sub","bob"},{"obj","data2"},{"act","write"} };
            TestEnforce(e, params, true);
        }
    };
}

#endif // TEST_ENFORCER_CPP
