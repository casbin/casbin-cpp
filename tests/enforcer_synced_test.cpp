/*
* Copyright 2020 The casbin Authors. All Rights Reserved.
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
* This is a test file showcasing the workflow of casbin::CachedEnforcer
*/

#include <gtest/gtest.h>
#include <casbin/casbin.h>

// TEST(TestEnforcerSynced, TestSync) {
//     std::string model = "../../examples/basic_model.conf";
//     std::string policy = "../../examples/basic_policy.csv";
//     casbin::SyncedEnforcer e(model, policy);

//     using namespace std::literals::chrono_literals;
//     auto time1 = 200ms;
//     e.StartAutoLoadPolicy(time1);

//     EXPECT_TRUE(e.Enforce({ "alice", "data1", "read" }));
//     EXPECT_FALSE(e.Enforce({ "alice", "data1", "write" }));
//     EXPECT_FALSE(e.Enforce({ "alice", "data2", "read" }));
//     EXPECT_FALSE(e.Enforce({ "alice", "data2", "write" }));
//     EXPECT_FALSE(e.Enforce({ "bob", "data1", "read" }));
//     EXPECT_FALSE(e.Enforce({ "bob", "data1", "write" }));
//     EXPECT_FALSE(e.Enforce({ "bob", "data2", "read" }));
//     EXPECT_TRUE(e.Enforce({ "bob", "data2", "write" }));

//     e.StopAutoLoadPolicy();
// }

// TEST(TestEnforcerSynced, TestStopLoadPolicy) {
//     std::string model = "../../examples/basic_model.conf";
//     std::string policy = "../../examples/basic_policy.csv";
//     casbin::SyncedEnforcer e(model, policy);

//     using namespace std::literals::chrono_literals;
//     std::chrono::duration<int64_t, std::nano> t = 5ms;

//     e.StartAutoLoadPolicy(t);

//     EXPECT_EQ(e.IsAutoLoadingRunning(), true);

//     ASSERT_EQ(e.Enforce({ "alice", "data1", "read" }), true);
//     ASSERT_EQ(e.Enforce({ "alice", "data1", "write" }), false);
//     ASSERT_EQ(e.Enforce({ "alice", "data2", "read" }), false);
//     ASSERT_EQ(e.Enforce({ "alice", "data2", "write" }), false);
//     ASSERT_EQ(e.Enforce({ "bob", "data1", "read" }), false);
//     ASSERT_EQ(e.Enforce({ "bob", "data1", "write" }), false);
//     ASSERT_EQ(e.Enforce({ "bob", "data2", "read" }), false);
//     ASSERT_EQ(e.Enforce({ "bob", "data2", "write" }), true);

//     e.StopAutoLoadPolicy();
//     std::this_thread::sleep_for(10ms);

//     EXPECT_EQ(e.IsAutoLoadingRunning(), false);
// }
