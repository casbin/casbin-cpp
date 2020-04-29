#include "pch.h"
#include "../casbin/config/config.h"

TEST(ConfigTest, MainTest) {


	Config cfg = Config::NewConfigFromFile("testdata/configTest.ini");
	string s;
	vector<string> vs;
	bool b;
	double d;
	int i;
	long l;

	b = cfg.Bool("debug");
	EXPECT_EQ(b,true);

	s = cfg.String("url");
	EXPECT_EQ(s, "act.wiki");

	vs = cfg.Strings("redis::redis.key");
	EXPECT_EQ(vs.size(), 2);
	EXPECT_EQ(vs[0], "push1");
	EXPECT_EQ(vs[1], "push2");

	s = cfg.String("mysql::mysql.dev.host");
	EXPECT_EQ(s, "127.0.0.1");

	s = cfg.String("mysql::mysql.master.host");
	EXPECT_EQ(s, "10.0.0.1");

	cfg.Set("other::key1", "new test key");
	s = cfg.String("other::key1");



	EXPECT_EQ(s, "new test key");

	l = cfg.Long("math::math.i64");
	EXPECT_EQ(l, 64);

	d = cfg.Double("math::math.f64");
	EXPECT_EQ(d, 64.1);



	s = cfg.String("multi1::name");
	EXPECT_EQ(s, "r.sub==p.sub && r.obj==p.obj");

	s = cfg.String("multi2::name");
	EXPECT_EQ(s, "r.sub==p.sub && r.obj==p.obj");

	s = cfg.String("multi3::name");
	EXPECT_EQ(s, "r.sub==p.sub && r.obj==p.obj");

	s = cfg.String("multi4::name");
	EXPECT_EQ(s, "");

	s = cfg.String("multi5::name");
	EXPECT_EQ(s, "r.sub==p.sub && r.obj==p.obj");

}