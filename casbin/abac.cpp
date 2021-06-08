#include "pch.h"

#ifndef ABAC_CPP
#define ABAC_CPP

#include "abac.h"

namespace casbin {

ABACData::ABACData(const std::unordered_map<std::string, std::string>& attrib)
        : m_attributes(attrib)
{}

ABACData::ABACData(const std::vector<std::vector<std::string>>& attributes) {
    for(auto attrib : attributes) {
        m_attributes[attrib[0]] = attrib[1];
    }
}

bool ABACData::AddAttribute(const std::string& key, const std::string& value) {
    m_attributes[key] = value;
    return true;
}

bool ABACData::AddAttributes(const std::vector<std::vector<std::string>>& attribs) {
    for(auto attrib : attribs) {
        m_attributes[attrib[0]] = attrib[1];
    }
    return true;
}

bool ABACData::DeleteAttribute(const std::string& key) {
    auto it = m_attributes.find(key);
    if(it == m_attributes.end()) {
        return false;
    }
    m_attributes.erase(it);
    return true;
}

bool ABACData::UpdateAttribute(const std::string& key, const std::string& value) {
    m_attributes[key] = value;
    return true;
}

const std::unordered_map<std::string, std::string>& ABACData::GetAttributes() {
    return m_attributes;
}

}

#endif // ABAC_CPP
