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
*/

#include <string>
#include <variant>
#include <vector>
#include <initializer_list>
#include <unordered_map>
#include "abac_data.h"

namespace casbin {

typedef std::variant<std::string, std::shared_ptr<ABACData>> Data;
typedef std::vector<Data> DataVector;
typedef std::initializer_list<Data> DataList;
typedef std::unordered_map<std::string, Data> DataMap;

} // namespace casbin
