#include <string>

#include "../casbin/util/split.h"
#include "pch.h"

using namespace std;

class TestModel : public ::testing::Test {
	protected:

		string filePath(string filepath) {
			char* root = _getcwd(NULL, 0);
			string rootStr = string(root);

			vector <string> directories = Split(rootStr, "\\", -1);
			vector <string> left{ "casbin-cpp" };
			vector <string> ::iterator it = find_end(directories.begin(), directories.end(), left.begin(), left.end());
			int index = directories.size() + (it - directories.end());

			vector <string> finalDirectories(directories.begin(), directories.begin() + index + 1);

			vector<string> userD = split(filepath, "/", -1);
			for (int i = 1; i < userD.size(); i++)
				finalDirectories.push_back(userD[i]);

			string filepath1 = finalDirectories[0];
			for (int i = 1; i < finalDirectories.size(); i++)
				filepath1 = filepath1 + "/" + finalDirectories[i];
			return filepath1;
		}
};

TEST_F(TestModel, TestDebug) {
	EXPECT_TRUE(config.getBool("debug"));
}

TEST_F(TestConfig, TestURL) {
	EXPECT_EQ("act.wiki", config.getString("url"));
}

TEST_F(TestConfig, TestRedis) {
	vector <string> values = config.getStrings("redis::redis.key");
	EXPECT_EQ("push1", values[0]);
	EXPECT_EQ("push2", values[1]);
}

TEST_F(TestConfig, TestMYSQLDEV) {
	EXPECT_EQ("127.0.0.1", config.getString("mysql::mysql.dev.host"));
}

TEST_F(TestConfig, TestMYSQLMASTER) {
	EXPECT_EQ("10.0.0.1", config.getString("mysql::mysql.master.host"));
}

TEST_F(TestConfig, TestMathInt) {
	EXPECT_EQ(64, config.getInt("math::math.i64"));
}

TEST_F(TestConfig, TestMathFloat) {
	EXPECT_EQ(float(64.1), config.getFloat("math::math.f64"));
}

TEST_F(TestConfig, TestSetConfig) {
	config.set("other::key1", "new test key");
	EXPECT_EQ("new test key", config.getString("other::key1"));
}

TEST_F(TestConfig, TestMulti) {
	EXPECT_EQ("r.sub==p.sub && r.obj==p.obj", config.getString("multi1::name"));
}