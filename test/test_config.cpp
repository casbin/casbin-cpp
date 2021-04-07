#include "pch.h"

#ifndef TEST_CONFIG_CPP
#define TEST_CONFIG_CPP


#include <config.h>
#include <util.h>

namespace test_config
{
    using namespace casbin;

    TEST_CLASS(TestConfig)
    {
        public:

            std::shared_ptr<Config> config;

            TEST_METHOD_INITIALIZE(InitializeConfig) {
                std::string filepath = "../../casbin/config/testdata/testini.ini";
                config = Config::NewConfig(filepath);
            }

            TEST_METHOD(TestDebug) {
                Assert::IsTrue(config->GetBool("debug"));
            }

            TEST_METHOD(TestURL) {
                Assert::AreEqual(std::string("act.wiki"), config->GetString("url"));
            }

            TEST_METHOD(TestRedis) {
                std::vector<std::string> values = config->GetStrings("redis::redis.key");
                Assert::AreEqual(std::string("push1"), values[0]);
                Assert::AreEqual(std::string("push2"), values[1]);
            }

            TEST_METHOD(TestMYSQLDEV) {
                Assert::AreEqual(std::string("127.0.0.1"), config->GetString("mysql::mysql.dev.host"));
            }

            TEST_METHOD(TestMYSQLMASTER) {
                Assert::AreEqual(std::string("10.0.0.1"), config->GetString("mysql::mysql.master.host"));
            }

            TEST_METHOD(TestMathInt) {
                Assert::AreEqual(64, config->GetInt("math::math.i64"));
            }

            TEST_METHOD(TestMathFloat) {
                Assert::AreEqual(float(64.1), config->GetFloat("math::math.f64"));
            }

            TEST_METHOD(TestSetConfig) {
                config->Set("other::key1", "new test key");
                Assert::AreEqual(std::string("new test key"), config->GetString("other::key1"));
            }

            TEST_METHOD(TestMulti) {
                Assert::AreEqual(std::string("r.sub==p.sub && r.obj==p.obj"), config->GetString("multi1::name"));
            }
    };
}

#endif // TEST_CONFIG_CPP
