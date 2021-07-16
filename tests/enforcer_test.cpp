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

#include <gtest/gtest.h>
#include <casbin/casbin.h>

namespace {

TEST(TestEnforcer, TestFourParams) {
    std::string model = "../../examples/rbac_with_domains_model.conf";
    std::string policy = "../../examples/rbac_with_domains_policy.csv";
    casbin::Enforcer e = casbin::Enforcer(model, policy);

    ASSERT_EQ(e.Enforce({ "alice", "domain1", "data1", "read" }), true);
    ASSERT_EQ(e.Enforce({ "alice", "domain1", "data1", "write" }), true);
    ASSERT_EQ(e.Enforce({ "alice", "domain1", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "domain1", "data2", "write" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "domain2", "data1", "read" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "domain2", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "domain2", "data2", "read" }), true);
    ASSERT_EQ(e.Enforce({ "bob", "domain2", "data2", "write" }), true);
}

TEST(TestEnforcer, TestThreeParams) {
    std::string model = "../../examples/basic_model_without_spaces.conf";
    std::string policy = "../../examples/basic_policy.csv";
    casbin::Enforcer e(model, policy);

    ASSERT_EQ(e.Enforce({ "alice", "data1", "read" }), true);
    ASSERT_EQ(e.Enforce({ "alice", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "write" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data1", "read" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data2", "write" }), true);
}

TEST(TestEnforcer, TestVectorParams) {
    std::string model = "../../examples/basic_model_without_spaces.conf";
    std::string policy = "../../examples/basic_policy.csv";
    casbin::Enforcer e(model, policy);

    ASSERT_EQ(e.Enforce({ "alice", "data1", "read" }), true);
    ASSERT_EQ(e.Enforce({ "alice", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "write" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data1", "read" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "bob", "data2", "write" }), true);
}

TEST(TestEnforcer, TestMapParams) {
    std::string model = "../../examples/basic_model_without_spaces.conf";
    std::string policy = "../../examples/basic_policy.csv";
    casbin::Enforcer e(model, policy);

    casbin::DataMap params = {{"sub", "alice"}, {"obj", "data1"}, {"act", "read"}};
    ASSERT_EQ(e.Enforce(params), true);

    params = { {"sub","alice"},{"obj","data1"},{"act","write"} };
    ASSERT_EQ(e.Enforce(params), false);

    params = { {"sub","alice"},{"obj","data2"},{"act","read"} };
    ASSERT_EQ(e.Enforce(params), false);

    params = { {"sub","alice"},{"obj","data2"},{"act","write"} };
    ASSERT_EQ(e.Enforce(params), false);

    params = { {"sub","bob"},{"obj","data1"},{"act","read"} };
    ASSERT_EQ(e.Enforce(params), false);

    params = { {"sub","bob"},{"obj","data1"},{"act","write"} };
    ASSERT_EQ(e.Enforce(params), false);

    params = { {"sub","bob"},{"obj","data2"},{"act","read"} };
    ASSERT_EQ(e.Enforce(params), false);

    params = { {"sub","bob"},{"obj","data2"},{"act","write"} };
    ASSERT_EQ(e.Enforce(params), true);
}

TEST(TestEnforcer, ABACData) {
    casbin::AttributeMap params = {
        { "Name", "Yash" },
        { "Grade", 8.6f },
        { "Age", 18 },
    };

    auto data = casbin::GetDataObject(params);
    ASSERT_TRUE(params == data->GetAttributes());

    data->DeleteAttribute("Name");
    params = {
        { "Grade", 8.6f },
        { "Age", 18 },
    };
    ASSERT_TRUE(params == data->GetAttributes());

    data->AddAttribute("ID", 156);
    params["ID"] = 156;
    ASSERT_TRUE(params == data->GetAttributes());

    data->UpdateAttribute("ID", 152);
    params["ID"] = 152;
    ASSERT_TRUE(params == data->GetAttributes());
}

} // namespace
