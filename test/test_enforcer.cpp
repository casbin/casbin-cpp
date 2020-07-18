#pragma once

#include "pch.h"

#include <enforcer.h>
#include <persist.h>
#include <rbac.h>
#include <util.h>

using namespace std;

namespace test_enforcer
{
    TEST_CLASS(TestEnforcer)
    {
    public:

        void TestEnforce(unique_ptr<Enforcer>& e, string sub, string dom, string obj, string act, bool res) {
            Assert::AreEqual(res, e->Enforce({sub, dom, obj, act}));
        }

        void TestEnforce(unique_ptr<Enforcer>& e, string sub, string obj, string act, bool res) {
            Assert::AreEqual(res, e->Enforce({sub, obj, act}));
        }

        void TestEnforce(unique_ptr<Enforcer>& e, vector<string> params, bool res) {
            Assert::AreEqual(res, e->Enforce(params));
        }

        void TestEnforce(unique_ptr<Enforcer>& e, unordered_map<string,string> params, bool res) {
            Assert::AreEqual(res, e->Enforce(params));
        }


        TEST_METHOD(TestFourParams) {

            string model = "../../examples/rbac_with_domains_model.conf";
            string policy = "../../examples/rbac_with_domains_policy.csv";
            unique_ptr<Enforcer> e = Enforcer::NewEnforcer(model, policy);

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
            string model = "../../examples/basic_model_without_spaces.conf";
            string policy = "../../examples/basic_policy.csv";
            unique_ptr<Enforcer> e = Enforcer::NewEnforcer(model, policy);

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
            string model = "../../examples/basic_model_without_spaces.conf";
            string policy = "../../examples/basic_policy.csv";
            unique_ptr<Enforcer> e = Enforcer::NewEnforcer(model, policy);

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
            string model = "../../examples/basic_model_without_spaces.conf";
            string policy = "../../examples/basic_policy.csv";
            unique_ptr<Enforcer> e = Enforcer::NewEnforcer(model, policy);

            unordered_map<string, string> params = { {"sub","alice"},{"obj","data1"},{"act","read"} };
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