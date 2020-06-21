#pragma once

#include "pch.h"

#include <direct.h>
#include <algorithm>
#include <fstream>

#include <util.h>
#include <model.h>
#include <config.h>
#include <exception.h>

using namespace std;

namespace test_model
{
    TEST_CLASS(TestModel)
    {
        public:

            string basic_example;
            Config* basic_config;

            TEST_METHOD_INITIALIZE(InitializeBasicConfig) {
                basic_example = filePath("../examples/basic_model.conf");
                basic_config = Config::NewConfig(basic_example);
            }

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

            TEST_METHOD(TestNewModel) {
                Model* model = Model::NewModel();
                Assert::IsNotNull(model);
            }

            TEST_METHOD(TestNewModelFromFile) {
                Model* model = Model::NewModelFromFile(basic_example);
                Assert::IsNotNull(model);
            }

            TEST_METHOD(TestNewModelFromString) {
                ifstream infile;
                infile.open(basic_example);
                string content;
                getline(infile, content, '\0');
                Model* model = Model::NewModelFromString(content);

                Assert::IsNotNull(model);
            }

            TEST_METHOD(TestLoadModelFromConfig) {
                Model* model = Model::NewModel();
                model->LoadModelFromConfig(basic_config);

                model = Model::NewModel();
                Config* config = Config::NewConfigFromText("");
                try {
                    model->LoadModelFromConfig(config);
                    Assert::Fail();
                }
                catch (MissingRequiredSections e) {
                }
            }

            TEST_METHOD(TestHasSection) {
                Model* model = Model::NewModel();
                model->LoadModelFromConfig(basic_config);

                for (int i = 0; i < (Model::required_sections).size(); i++) {
                    Assert::IsTrue(model->HasSection((Model::required_sections)[i]));
                }

                model = Model::NewModel();
                Config* config = Config::NewConfigFromText("");
                try {
                    model->LoadModelFromConfig(config);
                    Assert::Fail();
                }
                catch (MissingRequiredSections e) {
                }

                for (int i = 0; i < (Model::required_sections).size(); i++) {
                    Assert::IsFalse(model->HasSection((Model::required_sections)[i]));
                }
            }

            TEST_METHOD(TestModel_AddDef) {
                Model* model = Model::NewModel();
                string s = "r";
                string v = "sub, obj, act";

                bool ok = model->AddDef(s, s, v);
                Assert::IsTrue(ok);

                ok = model->AddDef(s, s, "");
                Assert::IsFalse(ok);
            }
    };
}