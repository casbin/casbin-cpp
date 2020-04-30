#include "pch.h"
#include "../casbin/config/config.h"

TEST(ConfigTest, MainTest) {


	Config cfg = Config::NewConfigFromFile("testdata/configTest.ini");

	EXPECT_EQ(cfg.Bool("debug"),true);
	EXPECT_EQ(cfg.String("url") , "act.wiki");

	vector<string>vs = cfg.Strings("redis::redis.key");
	EXPECT_EQ(vs.size(), 2);
	EXPECT_EQ(vs[0], "push1");
	EXPECT_EQ(vs[1], "push2");

	EXPECT_EQ(cfg.String("mysql::mysql.dev.host"), "127.0.0.1");
	EXPECT_EQ(cfg.String("mysql::mysql.master.host"), "10.0.0.1");

	cfg.Set("other::key1", "new test key");

	EXPECT_EQ(cfg.String("other::key1"), "new test key");
	EXPECT_EQ(cfg.Long("math::math.i64"), 64);
	EXPECT_EQ(cfg.Double("math::math.f64"), 64.1);


	EXPECT_EQ(cfg.String("multi1::name"), "r.sub==p.sub && r.obj==p.obj");
	EXPECT_EQ(cfg.String("multi2::name"), "r.sub==p.sub && r.obj==p.obj");
	EXPECT_EQ(cfg.String("multi3::name"), "r.sub==p.sub && r.obj==p.obj");
	EXPECT_EQ(cfg.String("multi4::name"), "");
	EXPECT_EQ(cfg.String("multi5::name"), "r.sub==p.sub && r.obj==p.obj");

}