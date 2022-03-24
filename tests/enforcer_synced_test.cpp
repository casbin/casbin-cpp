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
 * This is a test file showcasing the workflow of casbin::SyncedEnforcer
 */

#include <casbin/casbin.h>
#include <gtest/gtest.h>

#include "config_path.h"

namespace {

void TestSyncFn(casbin::SyncedEnforcer& e, const std::string& sub, const std::string& obj, const std::string& act, bool control) {
    bool response = e.Enforce({sub, obj, act});
    ASSERT_EQ(response, control);
}

TEST(TestEnforcerSynced, TestSync) {
    casbin::SyncedEnforcer e(basic_model_path, basic_policy_path);

    using namespace std::literals::chrono_literals;
    auto time1 = 200ms;
    e.StartAutoLoadPolicy(time1);

    TestSyncFn(e, "alice", "data1", "read", true);
    TestSyncFn(e, "alice", "data1", "write", false);
    TestSyncFn(e, "alice", "data2", "read", false);
    TestSyncFn(e, "alice", "data2", "write", false);
    TestSyncFn(e, "bob", "data1", "read", false);
    TestSyncFn(e, "bob", "data1", "write", false);
    TestSyncFn(e, "bob", "data2", "read", false);
    TestSyncFn(e, "bob", "data2", "write", true);

    std::this_thread::sleep_for(200ms);
    e.StopAutoLoadPolicy();
}

TEST(TestEnforcerSynced, TestStopLoadPolicy) {
    casbin::SyncedEnforcer e(basic_model_path, basic_policy_path);

    using namespace std::literals::chrono_literals;
    std::chrono::duration<int64_t, std::nano> t = 5ms;

    e.StartAutoLoadPolicy(t);

    EXPECT_EQ(e.IsAutoLoadingRunning(), true);

    TestSyncFn(e, "alice", "data1", "read", true);
    TestSyncFn(e, "alice", "data1", "write", false);
    TestSyncFn(e, "alice", "data2", "read", false);
    TestSyncFn(e, "alice", "data2", "write", false);
    TestSyncFn(e, "bob", "data1", "read", false);
    TestSyncFn(e, "bob", "data1", "write", false);
    TestSyncFn(e, "bob", "data2", "read", false);
    TestSyncFn(e, "bob", "data2", "write", true);

    e.StopAutoLoadPolicy();
    std::this_thread::sleep_for(10ms);

    EXPECT_EQ(e.IsAutoLoadingRunning(), false);
}

} // namespace
