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

#ifndef CASBIN_CPP_MODEL_ASSERTION
#define CASBIN_CPP_MODEL_ASSERTION

#include <memory>
#ifdef HASHED_POLICIES_VALUES

#include <unordered_set>
template<>
struct std::hash<std::vector<std::string>> {
       auto operator()(const std::vector<std::string>& rules) const -> size_t {
               size_t result = 0;
               for(const auto& rule : rules) {
                       result ^= std::hash<std::string>{}(rule);
               }
               return result;
       }
};

#endif

#include "../rbac/role_manager.h"

namespace casbin {

template<class Collection>
void addElement(Collection&, const typename Collection::value_type&);

enum policy_op { policy_add, policy_remove };
typedef enum policy_op policy_op;

using PolicyValues = std::vector<std::string>;

#ifdef HASHED_POLICIES_VALUES
using PoliciesValues = std::unordered_set<PolicyValues>;
template<>
void addElement(PoliciesValues& collection, const PoliciesValues::value_type& value) {
	collection.emplace(value);
}
#else
using PoliciesValues = std::vector<PolicyValues>;
template<>
void addElement(PoliciesValues& collection, const PoliciesValues::value_type& value) {
	collection.push_back(value);
}
#endif

// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act
class Assertion {
public:
    std::string key;
    std::string value;
    std::vector<std::string> tokens;
    PoliciesValues policy;
    std::shared_ptr<RoleManager> rm;

    void BuildIncrementalRoleLinks(std::shared_ptr<RoleManager>& rm, policy_op op, const PoliciesValues& rules);

    void BuildRoleLinks(std::shared_ptr<RoleManager>& rm);
};

}; // namespace casbin

#endif
