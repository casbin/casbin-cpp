#include "pch.h"

#ifndef TEST_MODEL_CPP
#define TEST_MODEL_CPP


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
            shared_ptr<Config> basic_config;

            TEST_METHOD_INITIALIZE(InitializeBasicConfig) {
                basic_example = "../../examples/basic_model.conf";
                basic_config = Config::NewConfig(basic_example);
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
                shared_ptr<Config> config = Config::NewConfigFromText("");
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
                shared_ptr<Config> config = Config::NewConfigFromText("");
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

#endif // TEST_MODEL_CPP
