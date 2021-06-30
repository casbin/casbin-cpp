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

static void BenchmarkCachedBasicModel(benchmark::State& state) {
    casbin::CachedEnforcer e("../../../examples/basic_model.conf", "../../../examples/basic_policy.csv");
    std::vector<std::string> request = {"alice", "data1", "read"};
    for (auto _ : state)
        e.Enforce(request);
}

BENCHMARK(BenchmarkCachedBasicModel);


static void BenchmarkCachedRBACModel(benchmark::State& state) {
    casbin::CachedEnforcer e("../../../examples/rbac_model.conf", "../../../examples/rbac_policy.csv");
    std::vector<std::string> request = {"alice", "data2", "read"};
    for (auto _ : state)
        e.Enforce(request);
}

BENCHMARK(BenchmarkCachedRBACModel);
