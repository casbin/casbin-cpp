#pragma once

#include <direct.h>
#include <algorithm>

#include "pch.h"
#include "../casbin/config/config.h"
#include "../casbin/util/util.h"

using namespace std;

class TestConfig : public ::testing::Test {
	protected:
		
		Config* config;

		void SetUp() override {
			string filepath = filePath("../casbin/config/testdata/testini.ini");
			config = Config :: NewConfig(filepath);
		}

		string filePath(string filepath) {
			char* root = _getcwd(NULL, 0);
			string rootStr = string(root);

			vector <string> directories = Split(rootStr, "\\", -1);
			vector <string> left{ "casbin-cpp" };
			vector <string> ::iterator it = find_end(directories.begin(), directories.end(), left.begin(), left.end());
			int index = directories.size() + (it - directories.end());

			vector <string> finalDirectories(directories.begin(), directories.begin() + index + 1);

			vector<string> userD = Split(filepath, "/", -1);
			for (int i = 1; i < userD.size(); i++)
				finalDirectories.push_back(userD[i]);

			string filepath1 = finalDirectories[0];
			for (int i = 1; i < finalDirectories.size(); i++)
				filepath1 = filepath1 + "/" + finalDirectories[i];
			return filepath1;
		}
};

TEST_F(TestConfig, TestDebug) {
	EXPECT_TRUE(config->GetBool("debug"));
}

TEST_F(TestConfig, TestURL) {
	EXPECT_EQ( "act.wiki", config->GetString("url"));
}

TEST_F(TestConfig, TestRedis) {
	vector<string> values = config->GetStrings("redis::redis.key");
	EXPECT_EQ("push1", values[0]);
	EXPECT_EQ("push2", values[1]);
}

TEST_F(TestConfig, TestMYSQLDEV) {
	EXPECT_EQ("127.0.0.1", config->GetString("mysql::mysql.dev.host"));
}

TEST_F(TestConfig, TestMYSQLMASTER) {
	EXPECT_EQ("10.0.0.1", config->GetString("mysql::mysql.master.host"));
}

TEST_F(TestConfig, TestMathInt) {
	EXPECT_EQ(64, config->GetInt("math::math.i64"));
}

TEST_F(TestConfig, TestMathFloat) {
	EXPECT_EQ(float(64.1), config->GetFloat("math::math.f64"));
}

TEST_F(TestConfig, TestSetConfig) {
	config->Set("other::key1", "new test key");
	EXPECT_EQ("new test key", config->GetString("other::key1"));
}

TEST_F(TestConfig, TestMulti) {
	EXPECT_EQ("r.sub==p.sub && r.obj==p.obj", config->GetString("multi1::name"));
}