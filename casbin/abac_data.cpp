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

#include "pch.h"

#ifndef ABAC_CPP
#define ABAC_CPP

#include "abac_data.h"
#include "./model/scope_config.h"

namespace casbin {

const std::shared_ptr<ABACData> GetData(const ABACData::VariantMap& attribs) {
    return std::make_shared<ABACData>(attribs);
}

ABACData::ABACData(const VariantMap& attrib)
        : m_attributes(attrib)
{}

bool ABACData::AddAttribute(const std::string& key, const VariantType& value) {
    m_attributes[key] = value;
    return true;
}

bool ABACData::AddAttributes(const VariantMap& attribs) {
    for(auto attrib : attribs) {
        m_attributes[attrib.first] = attrib.second;
    }
    return true;
}

bool ABACData::DeleteAttribute(const std::string& key) {
    auto it = m_attributes.find(key);

    // If key is not present in the map, indicate deletion failiure
    if(it == m_attributes.end()) {
        return false;
    }

    m_attributes.erase(it);
    return true;
}

bool ABACData::UpdateAttribute(const std::string& key, const VariantType& value) {
    m_attributes[key] = value;
    return true;
}

const ABACData::VariantMap& ABACData::GetAttributes() {
    return m_attributes;
}

}

#endif // ABAC_CPP
