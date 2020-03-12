#include "pch.h"
#include "../casbin/csv_adapter.h"
#include "../casbin/config.h"
#include "../casbin/model.h"
#include "../casbin/logger.h"

TEST(CSVAdapterTest, FileReadTest) {
	CSVAdapter e;
	e.readFile("../../examples/policy.csv");
	vector<vector<string>> data = e.getData();
	EXPECT_EQ(2, data.size()) << "The resulting size is " << data.size();
}

TEST(ConfAdapterTest, FileReadTest) {
	Config e;
	e.readFile("../../examples/model.conf");
	vector<string> data = e.getSections();
	EXPECT_EQ(4, data.size()) << "The resulting size is " << data.size();
}

TEST(ModelTest, FileReadTest) {
	Model m("../../examples/model.conf");
	EXPECT_EQ("r.sub == p.sub && r.obj == p.obj && r.act == p.act", m.getMatcherString()) << "The matcher string is " << m.getMatcherString();
	EXPECT_EQ("some(where (p.eft == allow))", m.getPolicyEffect()) << "The policy effect is " << m.getPolicyEffect();
}

TEST(ModelTest, RPTest) {
	Model m("../../examples/model.conf");
	map<string, vector<string>> structure = m.getRPStructure();
	EXPECT_EQ("r.sub,r.obj,r.act", join(structure.find("request_definition")->second, ',')) << "The request string is " << join(structure.find("request_definition")->second, ',');
	EXPECT_EQ("p.sub,p.obj,p.act", join(structure.find("policy_definition")->second, ',')) << "The request string is " << join(structure.find("policy_definition")->second, ',');
}

TEST(LogTest, WriteFileTest) {
	Logger log;
	log.print("Sample log");
}