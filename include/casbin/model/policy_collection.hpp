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

#pragma once

#include <unordered_set>


#ifdef HASHED_POLICIES_VALUES

template<>
struct std::hash<std::vector<std::string>> {
       auto operator()(const std::vector<std::string>& rules) const -> size_t {
               size_t result = 0;
               for(const auto& rule : rules)
                       result ^= std::hash<std::string>{}(rule);
               return result;
       }
};

#endif

namespace {

template<class Collection>
void addElement(Collection&, const typename Collection::value_type&);

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

} // namespace
