#pragma once

#include "pch.h"

#include <string>
#include <fstream>

#include <util.h>
#include <model.h>
#include <config.h>
#include <exception.h>

using namespace std;

class TestModel : public ::testing::Test {
	protected:

		string basic_example;
		Config* basic_config;

		void SetUp() override {
			basic_example = filePath("../examples/basic_model.conf");
			cout << basic_example << endl;
			basic_config = Config :: NewConfig(basic_example);
		}

		string filePath(string filepath) {
			char* root = _getcwd(NULL, 0);
			string rootStr = string(root);

			vector <string> directories = Split(rootStr, "\\", -1);
			vector <string> left{ "casbin-cpp" };
			vector <string> ::iterator it = find_end(directories.begin(), directories.end(), left.begin(), left.end());
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
};

TEST_F(TestModel, TestNewModel) {
	Model* model = Model :: NewModel();
	EXPECT_TRUE(model != NULL);
}

TEST_F(TestModel, TestNewModelFromFile) {
	cout << basic_example << endl;
	Model* model = Model :: NewModelFromFile(basic_example);
	cout << model << endl;
	EXPECT_TRUE(model != NULL);
}

TEST_F(TestModel, TestNewModelFromString) {
	ifstream infile;
	infile.open(basic_example);
	string content;
	getline(infile, content, '\0');
	Model* model = Model :: NewModelFromString(content);

	EXPECT_TRUE(model != NULL);
}

TEST_F(TestModel, TestLoadModelFromConfig) {
	Model* model = Model :: NewModel();
	model->LoadModelFromConfig(basic_config);
	
	model = Model :: NewModel();
	Config* config = Config :: NewConfigFromText("");
	try {
		model->LoadModelFromConfig(config);
		EXPECT_TRUE(false);
	}
	catch (MissingRequiredSections e) {
		EXPECT_TRUE(true);
	}
}

TEST_F(TestModel, TestHasSection) {
	Model* model = Model::NewModel();
	model->LoadModelFromConfig(basic_config);

	for (int i = 0; i < (Model::required_sections).size(); i++) {
		EXPECT_TRUE(model->HasSection((Model::required_sections)[i]));
	}

	model = Model::NewModel();
	Config* config = Config::NewConfigFromText("");
	try {
		model->LoadModelFromConfig(config);
		EXPECT_TRUE(false);
	}
	catch (MissingRequiredSections e) {
		EXPECT_TRUE(true);
	}

	for (int i = 0; i < (Model::required_sections).size(); i++) {
		EXPECT_FALSE(model->HasSection((Model::required_sections)[i]));
	}
}

TEST_F(TestModel, TestModel_AddDef) {
	Model* model = Model::NewModel();
	string s = "r";
	string v = "sub, obj, act";

	bool ok = model->AddDef(s, s, v);
	EXPECT_TRUE(ok);
	
	ok = model->AddDef(s, s, "");
	EXPECT_FALSE(ok);
}