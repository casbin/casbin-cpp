/*
 * Copyright 2021 The casbin Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is a test file showcasing the workflow of casbin::Enforcer
 */

#include <casbin/casbin.h>
#include <gtest/gtest.h>

#include "config_path.h"

namespace {

TEST(TestEnforcer, TestFourParams) {
    casbin::Enforcer e(rbac_with_domains_model_path, rbac_with_domains_policy_path);

    ASSERT_EQ(e.Enforce({"alice", "domain1", "data1", "read"}), true);
    ASSERT_EQ(e.Enforce({"alice", "domain1", "data1", "write"}), true);
    ASSERT_EQ(e.Enforce({"alice", "domain1", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "domain1", "data2", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "domain2", "data1", "read"}), false);
    ASSERT_EQ(e.Enforce({"bob", "domain2", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "domain2", "data2", "read"}), true);
    ASSERT_EQ(e.Enforce({"bob", "domain2", "data2", "write"}), true);
}

TEST(TestEnforcer, TestThreeParams) {
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    ASSERT_EQ(e.Enforce({"alice", "data1", "read"}), true);
    ASSERT_EQ(e.Enforce({"alice", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data1", "read"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data2", "write"}), true);
}

TEST(TestEnforcer, TestVectorParamsExplain) {
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    std::vector<std::vector<std::string>> explain(8);
    ASSERT_EQ(e.EnforceEx({"alice", "data1", "read"}, explain[0]), true);
    ASSERT_EQ(e.EnforceEx({"alice", "data1", "write"}, explain[1]), false);
    ASSERT_EQ(e.EnforceEx({"alice", "data2", "read"}, explain[2]), false);
    ASSERT_EQ(e.EnforceEx({"alice", "data2", "write"}, explain[3]), false);
    ASSERT_EQ(e.EnforceEx({"bob", "data1", "read"}, explain[4]), false);
    ASSERT_EQ(e.EnforceEx({"bob", "data1", "write"}, explain[5]), false);
    ASSERT_EQ(e.EnforceEx({"bob", "data2", "read"}, explain[6]), false);
    ASSERT_EQ(e.EnforceEx({"bob", "data2", "write"}, explain[7]), true);

    for (int i = 0; i < 8; i++) {
        std::cout << "EXPLAIN: ";
        for (int j = 0; j < explain[i].size(); j++) {
            std::cout << explain[i][j] << " ";
        }
        std::cout << std::endl;
    }
}

TEST(TestEnforcer, TestVectorParams) {
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    ASSERT_EQ(e.Enforce({"alice", "data1", "read"}), true);
    ASSERT_EQ(e.Enforce({"alice", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"alice", "data2", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data1", "read"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data1", "write"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data2", "read"}), false);
    ASSERT_EQ(e.Enforce({"bob", "data2", "write"}), true);
}

TEST(TestEnforcer, TestMapParams) {
    casbin::Enforcer e(basic_model_without_spaces_path, basic_policy_path);

    casbin::DataMap params = {{"sub", "alice"}, {"obj", "data1"}, {"act", "read"}};
    ASSERT_EQ(e.Enforce(params), true);

    params = {{"sub", "alice"}, {"obj", "data1"}, {"act", "write"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "alice"}, {"obj", "data2"}, {"act", "read"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "alice"}, {"obj", "data2"}, {"act", "write"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "bob"}, {"obj", "data1"}, {"act", "read"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "bob"}, {"obj", "data1"}, {"act", "write"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "bob"}, {"obj", "data2"}, {"act", "read"}};
    ASSERT_EQ(e.Enforce(params), false);

    params = {{"sub", "bob"}, {"obj", "data2"}, {"act", "write"}};
    ASSERT_EQ(e.Enforce(params), true);
}

// TEST(TestEnforcer, JsonData) {
//     using json = nlohmann::json;
//     casbin::Scope scope = casbin::InitializeScope();
//     casbin::PushObject(scope, "r");

//     json myJson = {
//             {"DoubleCase", 3.141},
//             {"IntegerCase", 2},
//             {"BoolenCase", true},
//             {"StringCase", "Bob"},
//             // {"nothing", nullptr},
//             {"x", {
//                     {"y", {
//                         {"z", 1}
//                         }
//                     },
//                     {"x", 2
//                     }
//                 }
//             },
//         };

//     casbin::PushObjectPropFromJson(scope, myJson, "r");
//     std::string s1 = "r.DoubleCase == 3.141;";
//     std::string s2 = "r.IntegerCase == 2;";
//     std::string s3 = "r.BoolenCase == true;";
//     std::string s4 = "r.StringCase == \"Bob\";";
//     std::string s5 = "r.x.y.z == 1;";
//     std::string s6 = "r.x.x == 2;";

//     auto EvalAndGetTop = [] (casbin::Scope scope, std::string s) -> bool  {
//        casbin::Eval(scope, s);
//        return casbin::GetBoolean(scope, -1);
//     };

//     ASSERT_TRUE(EvalAndGetTop(scope, s1));
//     ASSERT_TRUE(EvalAndGetTop(scope, s2));
//     ASSERT_TRUE(EvalAndGetTop(scope, s3));
//     ASSERT_TRUE(EvalAndGetTop(scope, s4));
//     ASSERT_TRUE(EvalAndGetTop(scope, s5));
//     ASSERT_TRUE(EvalAndGetTop(scope, s6));

//     s1 = "r.DoubleCase == 3.14;";
//     s2 = "r.IntegerCase == 1;";
//     s3 = "r.BoolenCase == false;";
//     s4 = "r.StringCase == \"BoB\";";
//     s5 = "r.x.y.z == 2;";
//     s6 = "r.x.x == 1;";

//     ASSERT_TRUE(!EvalAndGetTop(scope, s1));
//     ASSERT_TRUE(!EvalAndGetTop(scope, s2));
//     ASSERT_TRUE(!EvalAndGetTop(scope, s3));
//     ASSERT_TRUE(!EvalAndGetTop(scope, s4));
//     ASSERT_TRUE(!EvalAndGetTop(scope, s5));
//     ASSERT_TRUE(!EvalAndGetTop(scope, s6));
// }

} // namespace
