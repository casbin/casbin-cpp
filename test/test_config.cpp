#pragma once

#include "pch.h"

#include <direct.h>
#include <algorithm>

#include <config.h>
#include <util.h>

using namespace std;

namespace test_config
{
    TEST_CLASS(TestConfig)
    {
        public:

            Config* config;

            TEST_METHOD_INITIALIZE(InitializeConfig) {
                string filepath = filePath("/casbin/config/testdata/testini.ini");
                config = Config::NewConfig(filepath);
            }

            string filePath(string filepath) {
                char* root = _getcwd(NULL, 0);
                Logger::WriteMessage(root);
                string rootStr = string(root);

                vector <string> directories = Split(rootStr, "\\", -1);
                vector<string>::iterator it = find(directories.begin(), directories.end(), "x64");
                vector <string> left{ *(it-1) };
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

            TEST_METHOD(TestDebug) {
                Assert::IsTrue(config->GetBool("debug"));
            }

            TEST_METHOD(TestURL) {
                Assert::AreEqual(string("act.wiki"), config->GetString("url"));
            }

            TEST_METHOD(TestRedis) {
                vector<string> values = config->GetStrings("redis::redis.key");
                Assert::AreEqual(string("push1"), values[0]);
                Assert::AreEqual(string("push2"), values[1]);
            }

            TEST_METHOD(TestMYSQLDEV) {
                Assert::AreEqual(string("127.0.0.1"), config->GetString("mysql::mysql.dev.host"));
            }

            TEST_METHOD(TestMYSQLMASTER) {
                Assert::AreEqual(string("10.0.0.1"), config->GetString("mysql::mysql.master.host"));
            }

            TEST_METHOD(TestMathInt) {
                Assert::AreEqual(64, config->GetInt("math::math.i64"));
            }

            TEST_METHOD(TestMathFloat) {
                Assert::AreEqual(float(64.1), config->GetFloat("math::math.f64"));
            }

            TEST_METHOD(TestSetConfig) {
                config->Set("other::key1", "new test key");
                Assert::AreEqual(string("new test key"), config->GetString("other::key1"));
            }

            TEST_METHOD(TestMulti) {
                Assert::AreEqual(string("r.sub==p.sub && r.obj==p.obj"), config->GetString("multi1::name"));
            }
    };
}