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
* This is an intensive test file for benchmarking the performance of casbin::Model
*/

#include <benchmark/benchmark.h>
#include <casbin/casbin.h>
#include "config_path.h"

static const std::vector<std::vector<std::string>> s_policy = { {"alice", "data1", "read"}, {"bob", "data2", "write"} };
static void BenchmarkRBACModelMedium(benchmark::State& state) {
    casbin::Enforcer e(rbac_model_path);

    // 1000 roles, 100 resources.
    for (int i = 0; i < 1000; ++i)
        e.AddPolicy({"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"});

    // 10000 users.
    for (int i = 0; i < 10000; ++i)
        e.AddGroupingPolicy({"user" + std::to_string(i), "group" + std::to_string(i / 10)});

    casbin::DataList params = {"user5001", "data99", "read"};
    for (auto _ : state)
        e.Enforce(params);
}

BENCHMARK(BenchmarkRBACModelMedium);

static void BenchmarkRBACModelLarge(benchmark::State& state) {
    casbin::Enforcer e(rbac_model_path);

    // 10000 roles, 1000 resources.
    for(int i = 0; i < 10000; ++i)
        e.AddPolicy({"group" + std::to_string(i), "data" + std::to_string(i / 10), "read"});

    // 100000 users.
    for(int i = 0; i < 100000; i++)
        e.AddGroupingPolicy({"user" + std::to_string(i), "group" + std::to_string(i / 10)});

    casbin::DataList params = {"user50001", "data999", "read"};

    for(auto _ : state)
        e.Enforce(params);
}

BENCHMARK(BenchmarkRBACModelLarge);