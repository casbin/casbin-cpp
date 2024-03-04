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

#include "casbin/selected_policies.h"


bool SelectedPolicies::isHashCompliantMatcher(const std::string& matcher,const std::unordered_map<std::string, std::string>& request_tokens_values_map,
    std::shared_ptr<casbin::Model> model)
{
    auto tmp = matcher;
    for (const auto& [token, _ ] : request_tokens_values_map)
        tmp = regex_replace(tmp, std::regex("r." + token + " == p." + token), "");
    std::string expected = "";
    for (size_t i=0; i<request_tokens_values_map.size() - 1; i++)
        expected += " && ";
    return expected == tmp && model->m.find("g") != model->m.end();
}

std::vector<std::string> SelectedPolicies::policyValues()
{
        std::vector<std::string> ret;
        ret.reserve(policy_tokens.size());
        for(const auto& p : policy_tokens)
        {
            auto token = p.substr(2, p.size() - 2); // "p_token" -> "token"
            if (auto it = request_tokens_values_map.find(token); it != request_tokens_values_map.end()) {
                ret.emplace_back(it->second);
                continue;
            }
            throw std::logic_error("request and policy tokens names missmatch:" + p);
        }
        return ret;
}

SelectedPolicies::SelectedPolicies(
    const std::shared_ptr<casbin::IEvaluator>& evaluator, const std::string& matcher_, std::shared_ptr<casbin::Model> model,
    const PolicyValues& policy_tokens_)
    : request_tokens_values_map(evaluator->requestValues()),
    is_hash_compliant(isHashCompliantMatcher(matcher_, request_tokens_values_map, model)),
    unchanged_policies_values(model->m["p"].assertion_map["p"]->policy),
    mutated_policies_values(),
    policy_tokens(policy_tokens_)
{}

PoliciesValues& SelectedPolicies::operator*() {
#ifdef HASHED_POLICIES_VALUES
    if (is_hash_compliant) {
        mutated_policies_values = PoliciesValues{*unchanged_policies_values.find(policyValues())};
        return mutated_policies_values;
    }
#endif
    return unchanged_policies_values;
}

