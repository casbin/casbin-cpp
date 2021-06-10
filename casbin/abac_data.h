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

#ifndef ABAC_H
#define ABAC_H

#include <unordered_map>
#include <string>
#include <vector>
#include <variant>
#include <memory>

namespace casbin {

/**
 * @brief A wrapper to contain ABAC entity with a list of attributes stored in a hashmap
 * 
 */
class ABACData {

public:
// Array containing the reference to instantiated ABACData so far
static std::vector<std::shared_ptr<ABACData>> s_dataSet;

private:

    // Intrinsic definitions
    typedef std::variant<std::string, int32_t, float> VariantType;
    typedef std::unordered_map<std::string, VariantType> VariantMap;

    // HashMap containing attributes as key-value pairs
    VariantMap m_attributes;

public:
    /**
     * @brief Construct a new casbin::ABACData object
     * 
     * @param attribs Should be of the format: {
     * { "attrib_name1", value1 },
     * { "attring_name2", value2 },
     * ...
     * }
     * 
     * Key's type is std::string and value's type can be one of std::string, int32_t, and float only
     */
    ABACData(const VariantMap& attribs);
    /**
     * @brief Add attribute to the corresponding ABAC entity
     * 
     * @param key Name of the attribute
     * @param value Value of the attribute
     * @return true when attribute is added successfully, false otherwise
     */
    bool AddAttribute(const std::string& key, const VariantType& value);
    /**
     * @brief Add attributes to the corresponding ABAC entity
     * 
     * @param attribs Should be of the format: {
     * { "attrib_name1", value1 },
     * { "attring_name2", value2 },
     * ...
     * }
     * 
     * Key's type is std::string and value's type can be one of std::string, int32_t, and float only
     * @return true if attributes are added successfully, false otherwise
     */
    bool AddAttributes(const VariantMap& attribs);
    /**
     * @brief Delete attribute of the corresponding ABAC entity
     * 
     * @param key Name of the attribute to be deleted
     * @return true when attribute is deleted successfully, false otherwise
     */
    bool DeleteAttribute(const std::string& key);
    /**
     * @brief Update attribute of the corresponding ABAC entity
     * 
     * @param key Name of the attribute to be updated
     * @param value Value which would replace the current value of the attribute corresponding 
     * to the given key
     * @return true 
     * @return false 
     */
    bool UpdateAttribute(const std::string& key, const VariantType& value);
    /**
     * @brief Get the Attributes of the corresponding ABAC entity
     * 
     * @return const reference to the hashmap containing attributes in key-value pairs
     */
    const VariantMap& GetAttributes();
};

// Casbin ABAC entity type
typedef ABACData ABACData;

}

#endif
