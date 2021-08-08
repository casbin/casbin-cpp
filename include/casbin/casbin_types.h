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
* This is the main file for python bindings workflow
*/

#ifndef CASBIN_CPP_CASBIN_TYPES_H
#define CASBIN_CPP_CASBIN_TYPES_H

#include <variant>
#include <vector>
#include <initializer_list>
#include <unordered_map>

namespace casbin {

    typedef std::variant<std::string, int32_t, float, double> AttributeValue;
    typedef std::pair<std::string, AttributeValue> Attribute;
    typedef std::vector<Attribute> AttributeVector;
    typedef std::initializer_list<Attribute> AttributeList;
    typedef std::unordered_map<std::string, AttributeValue> AttributeMap;

    /**
     * @brief Get casbin::ABACData object
     *
     * @param attribs Should be of the format: {
     * { "attrib_name1", value1 },
     * { "attrib_name2", value2 },
     * ...
     * }
     *
     * Key's type is std::string and value's type can be one of std::string, int32_t, double, and float only
     * @return Pointer to casbin::ABACData entity
     */
    const std::shared_ptr<ABACData> GetDataObject(const AttributeMap& attribs);

    typedef std::variant<std::string, std::shared_ptr<ABACData>> Data;
    typedef std::vector<Data> DataVector;
    typedef std::initializer_list<Data> DataList;
    typedef std::unordered_map<std::string, Data> DataMap;

} // namespace casbin


#endif //CASBIN_CPP_CASBIN_TYPES_H
