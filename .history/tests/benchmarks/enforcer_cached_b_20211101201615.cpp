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
* This is a test file for benchmarking the performance of casbin::CachedEnforcer
*/

#include <benchmark/benchmark.h>
#include <casbin/casbin.h>
#include "config_path.h"

static void BenchmarkCachedBasicModel(benchmark::State& state) {
    casbin::CachedEnforcer e(basic_model_path, basic_policy_path);
    casbin::DataList request = {"alice", "data1", "read"};
    for (auto _ : state)
        e.Enforce(request);
}

BENCHMARK(BenchmarkCachedBasicModel);


static void BenchmarkCachedRBACModel(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_model_path, rbac_policy_path);
    casbin::DataList request = {"alice", "data2", "read"};
    for (auto _ : state)
        e.Enforce(request);
}

BENCHMARK(BenchmarkCachedRBACModel);

// ---- TODO ----
// static void BenchmarkCachedRaw(benchmark::State& state) {
//     for (auto _ : state)
//         rawEnforce("alice", "data1", "read")
// }

// BENCHMARK(BenchmarkCachedRaw);

static void BenchmarkCachedRBACModelSmall(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_model_path, "", false);
    // 100 roles, 10 resources.
    for (int i = 0; i < 100; ++i)
        e.AddPolicy({"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"});
    // 1000 users.
    for (int i = 0; i < 1000; ++i)
        e.AddGroupingPolicy({ "user" + std::to_string(i), "group", std::to_string(i / 10) });
    casbin::DataList params = {"user501", "data9", "read"};
    for (auto _ : state)
        e.Enforce(params);
}

BENCHMARK(BenchmarkCachedRBACModelSmall);

static void BenchmarkCachedRBACModelMedium(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_model_path, "", false);
    std::vector<std::vector<std::string>> p_policies(1000);
    // 1000 roles, 100 resources.
    for (int i = 0; i < 1000; ++i)
        p_policies[i] = { "group" + std::to_string(i), "data" + std::to_string(i / 10), "read" };

    e.AddPolicies(p_policies);

    // 10000 users.
    std::vector<std::vector<std::string>> g_policies(10000);
    for (int i = 0; i < 10000; ++i)
        g_policies[i] = { "user" + std::to_string(i), "group" + std::to_string(i/10) };

    e.AddGroupingPolicies(g_policies);
    casbin::DataList params = {"user5001", "data150", "read"};
    for (auto _ : state)
        e.Enforce(params);
}

// BENCHMARK(BenchmarkCachedRBACModelMedium);

static void BenchmarkCachedRBACModelLarge(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_model_path, "", false);

    // 10000 roles, 1000 resources.
    std::vector<std::vector<std::string>> p_policies(10000);
    for (int i = 0; i < 10000; ++i)
        p_policies[i] = {"group", std::to_string(i), "data", std::to_string(i / 10), "read"};
    e.AddPolicies(p_policies);

    // 100000 users.
    std::vector<std::vector<std::string>> g_policies(100000);
    for (int i = 0; i < 100000; ++i) {
        g_policies[i] = {"user" + std::to_string(i), "group", std::to_string(i / 10)};
    }
    e.AddGroupingPolicies(g_policies);
    casbin::DataList params = {"user50001", "data1500", "read"};
    for (auto _ : state)
    {
        e.Enforce(params);
    }
}

// BENCHMARK(BenchmarkCachedRBACModelLarge);

static void BenchmarkCachedRBACModelWithResourceRoles(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_with_resource_roles_model_path, rbac_with_resource_roles_policy_path, false);

    casbin::DataList params = {"alice", "data1", "read"};
    for (auto _ : state)
    {
        e.Enforce(params);
    }
}

BENCHMARK(BenchmarkCachedRBACModelWithResourceRoles);

static void BenchmarkCachedRBACModelWithDomains(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_with_domains_model_path, rbac_with_domains_policy_path, false);

    casbin::DataList params = {"alice", "domain1", "data1", "read"};

    for(auto _ : state)
    {
        e.Enforce(params);
    }
}

BENCHMARK(BenchmarkCachedRBACModelWithDomains);

// ---- TODO ----
// static void BenchmarkCachedABACModel(benchmark::State& state) {
//     casbin::CachedEnforcer e(abac_model_path, false);
//     auto data1 = casbin::GetData({
//         {"Name", "data1"},
//         {"Owner", "alice"}
//     });

//     casbin::DataList params = {"alice", data1, "read"};
//     for (auto _ : state)
//     {
//         e.Enforce(params);
//     }
// }

static void BenchmarkCachedKeyMatchModel(benchmark::State& state) {
    casbin::CachedEnforcer e(keymatch_model_path, keymatch_policy_path, false);
    casbin::DataList params = {"alice", "/alice_data/resource1", "GET"};
    for (auto _ : state)
    {
        e.Enforce(params);
    }
}

BENCHMARK(BenchmarkCachedKeyMatchModel);

static void BenchmarkCachedRBACModelWithDeny(benchmark::State& state) {
    casbin::CachedEnforcer e(rbac_with_deny_model_path, rbac_with_deny_policy_path, false);

    casbin::DataList params = {"alice", "data1", "read"};
    for (auto _ : state)
    {
        e.Enforce(params);
    }
}

BENCHMARK(BenchmarkCachedRBACModelWithDeny);

static void BenchmarkCachedPriorityModel(benchmark::State& state) {
    casbin::CachedEnforcer e(priority_model_path, priority_policy_path, false);

    casbin::DataList params = {"alice", "data1", "read"};

    for(auto _ : state)
        e.Enforce(params);
}

BENCHMARK(BenchmarkCachedPriorityModel);

static void BenchmarkCachedRBACModelMediumParallel(benchmark::State& state) {

    casbin::CachedEnforcer e(rbac_model_path, "", false);
    casbin::DataList params = {"user5001", "data150", "read"};
    if (state.thread_index == 0)
    {
        std::vector<std::vector<std::string>> p_policies(10000);
        for (int i = 0; i < 10000; ++i)
            p_policies[i] = { "group" + std::to_string(i), "data" + std::to_string(i / 10), "read" };
        e.AddPolicies(p_policies);

        std::vector<std::vector<std::string>> g_policies(100000);
        for (int i = 0; i < 100000; ++i)
            e.AddGroupingPolicy({ "user" + std::to_string(i), "group" + std::to_string(i/10) });
    }
    for (auto _ : state) {
        e.Enforce(params);
    }
}
// BENCHMARK(BenchmarkCachedRBACModelMediumParallel)->Threads(10);

