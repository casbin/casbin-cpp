#include "pch.h"

#ifndef ABAC_CPP
#define ABAC_CPP

#include "abac_data.h"
#include "./model/scope_config.h"

namespace casbin {

/**
 * @brief Get casbin::ABACData object
 * 
 * @param attribs Should be of the format: {
 * { "attrib_name1", value1 },
 * { "attrib_name2", value2 },
 * ...
 * }
 * 
 * Key's type is std::string and value's type can be one of std::string, int32_t, and float only
 * @return Pointer to casbin::ABACData entity
 */
static const std::shared_ptr<ABACData> GetData(const std::unordered_map<std::string, std::variant<std::string, int32_t, float>>& attribs) {
    return ABACData::s_dataSet.emplace_back(std::make_shared<ABACData>(attribs));
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
