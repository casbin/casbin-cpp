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
 */

#include "casbin/pch.h"

#pragma once

#include <algorithm>
#include <regex>

#include "casbin/model/policy_collection.hpp"
#include "casbin/model/evaluator.h"

class SelectedPolicies final {
private:
    std::unordered_map<std::string, std::string> request_tokens_values_map;
    const bool is_hash_compliant;
    PoliciesValues& unchanged_policies_values;
    PoliciesValues mutated_policies_values;
    PolicyValues policy_tokens;

    static bool isHashCompliantMatcher(const std::string& matcher,
        const std::unordered_map<std::string, std::string>& request_tokens_values_map,
	std::shared_ptr<casbin::Model> model);

    std::vector<std::string> policyValues();

public:
    SelectedPolicies(
        const std::shared_ptr<casbin::IEvaluator>& evaluator, const std::string& matcher_, std::shared_ptr<casbin::Model> model,
        const PolicyValues& policy_tokens_);
    PoliciesValues& operator*();
};
