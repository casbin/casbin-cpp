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

#include "pch.h"

#ifndef MODEL_CPP
#define MODEL_CPP


#include <sstream>

#include "./model.h"
#include "../config/config.h"
#include "../exception/missing_required_sections.h"
#include "../util/util.h"

namespace casbin {

std::unordered_map<std::string, std::string> Model::section_name_map = {
    {"r", "request_definition"},
    {"p", "policy_definition"},
    {"g", "role_definition"},
    {"e", "policy_effect"},
    {"m", "matchers"}
};

std::vector<std::string> Model::required_sections{"r","p","e","m"};

void Model::LoadModelFromConfig(std::shared_ptr<Config>& cfg) {
    for (auto [section_name, _] : section_name_map)
        LoadSection(this ,cfg, section_name);

    std::vector<std::string> ms;
    ms.reserve(required_sections.size());

    for(const std::string& required_section : required_sections)
        if(!this->HasSection(required_section)) 
            ms.push_back(section_name_map[required_section]);

    if(ms.size() > 0)
        throw MissingRequiredSections("missing required sections: " + Join(ms, ","));
}

bool Model::HasSection(const std::string& sec) {
    return this->m.find(sec) != this->m.end();
}

void Model::LoadSection(Model* raw_ptr, std::shared_ptr<ConfigInterface> cfg, const std::string& sec) {
    int i = 1;
    while(true) {
        if (!LoadAssertion(raw_ptr, cfg, sec, sec + GetKeySuffix(i)))
            break;
        else
            i++;
    }
}

std::string Model::GetKeySuffix(int i) {
    if (i == 1)
        return "";
    return std::to_string(i);
}

bool Model::LoadAssertion(Model* raw_ptr, std::shared_ptr<ConfigInterface> cfg, const std::string& sec, const std::string& key) {
    std::string value = cfg->GetString(section_name_map[sec] + "::" + key);
    return raw_ptr->AddDef(sec, key, value);
}

// AddDef adds an assertion to the model.
bool Model::AddDef(const std::string& sec, const std::string& key, const std::string& value) {
    if(value == "")
        return false;

    std::shared_ptr<Assertion> ast = std::make_shared<Assertion>();
    ast->key = key;
    ast->value = value;
    if (sec == "r" || sec == "p") {
        ast->tokens = Split(ast->value, ",");
        for (std::string& token : ast->tokens)
            token = key + "_" + Trim(token);
    }
    else
        ast->value = RemoveComments(ast->value);

    if (m.find(sec) == m.end())
        m[sec] = AssertionMap();
    ast->policy = {};

    m[sec].assertion_map[key] = ast;

    return true;
}

// LoadModel loads the model from model CONF file.
void Model::LoadModel(const std::string& path) {
    std::shared_ptr<Config> cfg = Config::NewConfig(path);
    LoadModelFromConfig(cfg);
}

// LoadModelFromText loads the model from the text.
void Model::LoadModelFromText(const std::string& text) {
    std::shared_ptr<Config> cfg = Config::NewConfigFromText(text);
    LoadModelFromConfig(cfg);
}

// PrintModel prints the model to the log.
void Model::PrintModel() {
    // ------TODO------
    // DefaultLogger df_logger;
    // df_logger.EnableLog(true);

    // Logger *logger = &df_logger;
    // LogUtil::SetLogger(*logger);

    // LogUtil::LogPrint("Model:");
    // for (unordered_map <std::string, AssertionMap>::iterator it1 = M.begin() ; it1 != M.end() ; it1++){
    // 	for(unordered_map <std::string, Assertion*>::iterator it2 = (it1->second).AMap.begin() ; it2 != (it1->second).AMap.end() ; it2++){
            // LogUtil::LogPrintf("%s.%s: %s", it1->first, it2->first, it2->second->Value);
    // 	}
    // }
}

Model::Model(){
}

Model::Model(const std::string& path){
    LoadModel(path);
}

// NewModel creates an empty model.
std::shared_ptr<Model> Model::NewModel() {
    return std::make_shared<Model>();
}

// NewModel creates a model from a .CONF file.
std::shared_ptr<Model> Model::NewModelFromFile(const std::string& path) {
    std::shared_ptr<Model> m = NewModel();
    m->LoadModel(path);
    return m;
}

// NewModel creates a model from a std::string which contains model text.
std::shared_ptr<Model> Model::NewModelFromString(const std::string& text) {
    std::shared_ptr<Model> m = NewModel();
    m->LoadModelFromText(text);
    return m;
}

void Model::BuildIncrementalRoleLinks(std::shared_ptr<RoleManager>& rm, policy_op op, const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules) {
    if (sec == "g")
        this->m[sec].assertion_map[p_type]->BuildIncrementalRoleLinks(rm, op, rules);
}

// BuildRoleLinks initializes the roles in RBAC.
void Model::BuildRoleLinks(std::shared_ptr<RoleManager>& rm) {
    for (auto [_, assertion_ptr] : this->m["g"].assertion_map)
        assertion_ptr->BuildRoleLinks(rm);
}

// PrintPolicy prints the policy to log.
void Model::PrintPolicy() {
    // ------TODO------
    // DefaultLogger df_logger;
    // df_logger.EnableLog(true);

    // Logger *logger = &df_logger;
    // LogUtil::SetLogger(*logger);

    // LogUtil::LogPrint("Policy:");

    // for (std::unordered_map<std::string, Assertion*>::iterator it = this->m["p"].assertion_map.begin() ; it != this->m["p"].assertion_map.end() ; it++) {
        // LogUtil::LogPrint(it->first, ": ", (it->second)->Value, ": ", (it->second)->policy);
    // }

    // for (std::unordered_map<std::string, Assertion*>::iterator it = this->m["g"].assertion_map.begin() ; it != this->m["g"].assertion_map.end() ; it++) {
        // LogUtil::LogPrint(it->first, ": ", (it->second)->Value, ": ", (it->second)->policy);
    // }
}

// ClearPolicy clears all current policy.
void Model::ClearPolicy() {
    // Caching "p" assertion map by reference for the scope of this function
    for (auto [_, assertion_ptr] : this->m["p"].assertion_map) {
        if(assertion_ptr->policy.size() > 0)
            assertion_ptr->policy.clear();
    }

    // Caching "g" assertion map by reference for the scope of this function
    for (auto [_, assertion_ptr] : this->m["g"].assertion_map){
        if(assertion_ptr->policy.size() > 0)
            assertion_ptr->policy.clear();
    }
}

// GetPolicy gets all rules in a policy.
std::vector<std::vector<std::string>> Model::GetPolicy(const std::string& sec, const std::string& p_type) {
    return this->m[sec].assertion_map[p_type]->policy;
}

// GetFilteredPolicy gets rules based on field filters from a policy.
std::vector<std::vector<std::string>> Model::GetFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values) {
    std::vector<std::vector<std::string>> res;
    const std::vector<std::vector<std::string>>& policy = m[sec].assertion_map[p_type]->policy;
    res.reserve(policy.size());
    for(int i = 0 ; i < policy.size() ; i++){
        bool matched = true;
        for(int j = 0 ; j < field_values.size() ; j++){
            if(field_values[j] != "" && (policy[i])[field_index + j] != field_values[j] ){
                matched = false;
                break;
            }
        }
        if(matched)
            res.push_back(policy[i]);
    }

    return res;
}

// HasPolicy determines whether a model has the specified policy rule.
bool Model::HasPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) {
    auto& policy = this->m[sec].assertion_map[p_type]->policy;
    for(const std::vector<std::string>& policy_it : policy)
        if (ArrayEquals(rule, policy_it))
            return true;

    return false;
}

// AddPolicy adds a policy rule to the model.
bool Model::AddPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) {
    if(!this->HasPolicy(sec, p_type, rule)) {
        m[sec].assertion_map[p_type]->policy.push_back(rule);
        return true;
    }

    return false;
}

// AddPolicies adds policy rules to the model.
bool Model::AddPolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules) {
    for (const std::vector<std::string>& rule : rules)
        if (this->HasPolicy(sec, p_type, rule))
            return false;

    for (const std::vector<std::string>& rule : rules)
        this->m[sec].assertion_map[p_type]->policy.push_back(rule);

    return true;
}

bool Model::UpdatePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) {
    // Caching policy by reference for the scope of this function
    auto& policy = m[sec].assertion_map[p_type]->policy;

    // Status flags
    bool is_oldRule_deleted = false, is_newRule_added = false;

    for (auto it = policy.begin(); it != policy.end(); ++it) {
        if(ArrayEquals(oldRule, *it)) {
            policy.erase(it);
            is_oldRule_deleted = true;
            break;
        }
    }

    if(!is_oldRule_deleted)
        return false;

    // Prevents duplicate policies
    if(!this->HasPolicy(sec, p_type, newRule)) {
        policy.push_back(newRule);
        is_newRule_added = true;
    }

    if(!is_newRule_added)
        return false;

    return is_oldRule_deleted && is_newRule_added;
}

bool Model::UpdatePolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& oldRules, const std::vector<std::vector<std::string>>& newRules) {
    // Caching policy by reference for the scope of this function
    auto& policy = this->m[sec].assertion_map[p_type]->policy;

    // Deleting old rules
    bool is_oldRule_deleted;
    for (const std::vector<std::string>& oldRule : oldRules) {
        is_oldRule_deleted = false;
        for (auto it = policy.begin(); it != policy.end(); ++it) {
            if(ArrayEquals(oldRule, *it)) {
                policy.erase(it);
                is_oldRule_deleted = true;
                break;
            }
        }
        if(!is_oldRule_deleted)
            return false;
    }

    // Checking if the policy already contains newRule
    for(const std::vector<std::string>& newRule : newRules) {
        if(!this->HasPolicy(sec, p_type, newRule))
            continue;
        else
            return false;
    }

    for(const std::vector<std::string>& newRule : newRules) {
        policy.push_back(newRule);
    }

    return true;
}

// RemovePolicy removes a policy rule from the model.
bool Model::RemovePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) {
    // Caching policy by reference for the scope of this function
    auto& policy = m[sec].assertion_map[p_type]->policy;
    for (auto it = policy.begin(); it != policy.end(); ++it) {
        if(ArrayEquals(rule, *it)) {
            policy.erase(it);
            return true;
        }
    }
    return false;
}

// RemovePolicies removes policy rules from the model.
bool Model::RemovePolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules) {
    // Caching policy by reference for the scope of this function
    auto& policy = this->m[sec].assertion_map[p_type]->policy;

    bool is_equal;
    for (const std::vector<std::string>& rule : rules) {
        is_equal = false;
        for (const std::vector<std::string>& policy_it : policy) {
            if (ArrayEquals(rule, policy_it))
                is_equal = true;
        }
        if(!is_equal)
            return false;
    }

    for (const std::vector<std::string>& rule : rules) {
        for (auto policy_it = policy.begin(); policy_it != policy.end(); ++policy_it) {
            if (ArrayEquals(rule, *policy_it))
                policy.erase(policy_it);
        }
    }

    return true;
}

// RemoveFilteredPolicy removes policy rules based on field filters from the model.
std::pair<bool, std::vector<std::vector<std::string>>> Model::RemoveFilteredPolicy(const std::string& sec, const std::string& p_type, int field_index, const std::vector<std::string>& field_values) {
    std::vector<std::vector<std::string>> tmp;
    std::vector<std::vector<std::string>> effects;
    std::vector<std::vector<std::string>>& policy = m[sec].assertion_map[p_type]->policy;
    tmp.reserve(policy.size());
    effects.reserve(policy.size());
    bool res = false;
    for(int i = 0 ; i < policy.size() ; i++) {
        bool matched = true;
        for (int j = 0 ; j < field_values.size() ; j++) {
            if (field_values[j] != "" && (policy[i])[field_index+j] != field_values[j]) {
                matched = false;
                break;
            }
        }
        if (matched){
            effects.push_back(policy[i]);
            res = true;
        }
        else
            tmp.push_back(policy[i]);
    }

    policy = tmp;
    std::pair<bool, std::vector<std::vector<std::string>>> result(res, effects);
    return result;
}

// GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
std::vector<std::string> Model::GetValuesForFieldInPolicy(const std::string& sec, const std::string& p_type, int field_index) {
    std::vector<std::string> values;
    std::vector<std::vector<std::string>>& policy = m[sec].assertion_map[p_type]->policy;
    values.reserve(policy.size());

    for (const std::vector<std::string>& policy_it : policy)
        values.push_back(policy_it[field_index]);

    ArrayRemoveDuplicates(values);

    return values;
}

// GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all p_types, duplicated values are removed.
std::vector<std::string> Model::GetValuesForFieldInPolicyAllTypes(const std::string& sec, int field_index) {
    std::vector<std::string> values;

    for (auto [assertion, _] : m[sec].assertion_map) {
        const std::vector<std::string>& values_for_field = this->GetValuesForFieldInPolicy(sec, assertion, field_index);
        for(const std::string& value_for_field : values_for_field)
            values.push_back(value_for_field);
    }

    ArrayRemoveDuplicates(values);

    return values;
}

} // namespace casbin

#endif // MODEL_CPP
