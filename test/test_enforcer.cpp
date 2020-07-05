#pragma once

#include "pch.h"

#include <direct.h>
#include <algorithm>

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

        string filePath(string filepath) {
            char* root = _getcwd(NULL, 0);
            string rootStr = string(root);

            vector <string> directories = Split(rootStr, "\\", -1);
            vector<string>::iterator it = find(directories.begin(), directories.end(), "x64");
            vector <string> left{ *(it - 1) };
            it = find_end(directories.begin(), directories.end(), left.begin(), left.end());
            int index = int(directories.size() + (it - directories.end()));

            vector <string> finalDirectories(directories.begin(), directories.begin() + index + 1);

            vector<string> userD = Split(filepath, "/", -1);
            for (int i = 1; i < userD.size(); i++)
                finalDirectories.push_back(userD[i]);

            string filepath1 = finalDirectories[0];
            for (int i = 1; i < finalDirectories.size(); i++)
                filepath1 = filepath1 + "/" + finalDirectories[i];
            return filepath1;
        }

        void TestEnforce(Enforcer* e, string sub, string dom, string obj, string act, bool res) {
            Assert::AreEqual(res, e->Enforce(sub, dom, obj, act));
        }

        void TestEnforce(Enforcer* e, string sub, string obj, string act, bool res) {
            Assert::AreEqual(res, e->Enforce(sub, obj, act));
        }

        void TestEnforce(Enforcer* e, string sub, string act, bool res) {
            Assert::AreEqual(res, e->Enforce(sub, act));
        }

        void TestEnforce(Enforcer* e, vector<string> params, bool res) {
            Assert::AreEqual(res, e->Enforce(params));
        }

        void TestEnforce(Enforcer* e, unordered_map<string,string> params, bool res) {
            Assert::AreEqual(res, e->Enforce(params));
        }


        TEST_METHOD(TestFourParams) {
            string model = filePath("../examples/rbac_with_domains_model.conf");
            string policy = filePath("../examples/rbac_with_domains_policy.csv");
            Enforcer* e = Enforcer::NewEnforcer(model, policy);

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
            string model = filePath("../examples/basic_model_without_spaces.conf");
            string policy = filePath("../examples/basic_policy.csv");
            Enforcer* e = Enforcer::NewEnforcer(model, policy);

            TestEnforce(e, { "alice", "data1", "read" }, true);
            TestEnforce(e, { "alice", "data1", "write" }, false);
            TestEnforce(e, { "alice", "data2", "read" }, false);
            TestEnforce(e, { "alice", "data2", "write" }, false);
            TestEnforce(e, { "bob", "data1", "read" }, false);
            TestEnforce(e, { "bob", "data1", "write" }, false);
            TestEnforce(e, { "bob", "data2", "read" }, false);
            TestEnforce(e, { "bob", "data2", "write" }, true);
        }

        TEST_METHOD(TestTwoParams) {
            string model = filePath("../examples/basic_without_users_model.conf");
            string policy = filePath("../examples/basic_without_users_policy.csv");
            Enforcer* e = Enforcer::NewEnforcer(model, policy);

            TestEnforce(e, "data1", "read", true);
            TestEnforce(e, "data1", "write", false);
            TestEnforce(e, "data2", "read", false);
            TestEnforce(e, "data2", "write", true);
        }
        
        TEST_METHOD(TestVectorParams) {
            string model = filePath("../examples/basic_model_without_spaces.conf");
            string policy = filePath("../examples/basic_policy.csv");
            Enforcer* e = Enforcer::NewEnforcer(model, policy);

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
            string model = filePath("../examples/basic_model_without_spaces.conf");
            string policy = filePath("../examples/basic_policy.csv");
            Enforcer* e = Enforcer::NewEnforcer(model, policy);

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