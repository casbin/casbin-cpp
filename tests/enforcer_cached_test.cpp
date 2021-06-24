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

TEST(TestEnforcerCached, TestCache) {
    std::string model = "../../examples/basic_model.conf";
    std::string policy = "../../examples/basic_policy.csv";
    casbin::CachedEnforcer e(model, policy);
    ASSERT_EQ(e.Enforce({ "alice", "data1", "read" }), true);
    ASSERT_EQ(e.Enforce({ "alice", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "write" }), false);

    // The cache is enabled, so even if we remove a policy rule, the decision
    // for ("alice", "data1", "read") will still be true, as it uses the cached result.
    e.RemovePolicy({ "alice", "data1", "read" });
    ASSERT_EQ(e.Enforce({ "alice", "data1", "read" }), true);
    ASSERT_EQ(e.Enforce({ "alice", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "write" }), false);

    // Now we invalidate the cache, then all first-coming Enforce() has to be evaluated in real-time.
    // The decision for ("alice", "data1", "read") will be false now.
    e.InvalidateCache();
    ASSERT_EQ(e.Enforce({ "alice", "data1", "read" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data1", "write" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "read" }), false);
    ASSERT_EQ(e.Enforce({ "alice", "data2", "write" }), false);
}