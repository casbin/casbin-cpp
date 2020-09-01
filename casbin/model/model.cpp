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

#include "pch.h"

#include <sstream>

#include "./model.h"
#include "../config/config.h"
#include "../exception/missing_required_sections.h"
#include "../util/util.h"

using namespace std;

unordered_map<string, string> Model :: section_name_map = {
    {"r", "request_definition"},
    {"p", "policy_definition"},
    {"g", "role_definition"},
    {"e", "policy_effect"},
    {"m", "matchers"}
};

vector<string> Model :: required_sections{"r","p","e","m"};

void Model :: LoadModelFromConfig(shared_ptr<ConfigInterface> cfg) {
    for(unordered_map <string, string> :: iterator it = section_name_map.begin() ; it != section_name_map.end() ; it++)
        LoadSection(this, cfg, it->first);

    vector<string> ms;
    for(int i=0 ; i < required_sections.size() ; i++)
        if(!this->HasSection(required_sections[i])) 
            ms.push_back(section_name_map[required_sections[i]]);

    if(ms.size() > 0)
        throw MissingRequiredSections("missing required sections: " + Join(ms, ","));
}

bool Model :: HasSection(string sec) {
    return this->m.find(sec) != this->m.end();
}

void Model :: LoadSection(Model* model, shared_ptr<ConfigInterface> cfg, string sec) {
    int i = 1;
    while(true) {
        if (!LoadAssertion(model, cfg, sec, sec+GetKeySuffix(i))){
            break;
        }
        else
            i++;
    }
}

string Model :: GetKeySuffix(int i) {
    if (i == 1)
        return "";
    stringstream ss;
    ss<<i;
    string s;
    ss>>s;
    return s;
}

bool Model :: LoadAssertion(Model* model, shared_ptr<ConfigInterface> cfg, string sec, string key) {
    string value = cfg->GetString(section_name_map[sec] + "::" + key);
    return model->AddDef(sec, key, value);
}

// AddDef adds an assertion to the model.
bool Model :: AddDef(string sec, string key, string value) {
    if(value == "")
        return false;

    shared_ptr<Assertion> ast(new Assertion());
    ast->key = key;
    ast->value = value;
    if (sec == "r" || sec == "p") {
        ast->tokens = Split(ast->value, ",");
        for (int i = 0; i < ast->tokens.size() ; i++)
            ast->tokens[i] = key + "_" + Trim(ast->tokens[i]);
    }
    else
        ast->value = RemoveComments(ast->value);

    if (m.find(sec) == m.end())
        m[sec] = AssertionMap();
    ast->policy = vector<vector<string>>{};

    m[sec].assertion_map[key] = ast;

    return true;
}

// LoadModel loads the model from model CONF file.
void Model :: LoadModel(string path) {
    shared_ptr<Config> cfg = Config::NewConfig(path);
    LoadModelFromConfig(cfg);
}

// LoadModelFromText loads the model from the text.
void Model :: LoadModelFromText(string text) {
    shared_ptr<Config> cfg = Config::NewConfigFromText(text);
    LoadModelFromConfig(cfg);
}

// PrintModel prints the model to the log.
void Model :: PrintModel() {
    // DefaultLogger df_logger;
    // df_logger.EnableLog(true);

    // Logger *logger = &df_logger;
    // LogUtil::SetLogger(*logger);

    // LogUtil::LogPrint("Model:");
    // for (unordered_map <string, AssertionMap> :: iterator it1 = M.begin() ; it1 != M.end() ; it1++){
    // 	for(unordered_map <string, Assertion*> :: iterator it2 = (it1->second).AMap.begin() ; it2 != (it1->second).AMap.end() ; it2++){
            // LogUtil::LogPrintf("%s.%s: %s", it1->first, it2->first, it2->second->Value);
    // 	}
    // }
}

Model :: Model(){
}

Model :: Model(string path){
    LoadModel(path);
}

// NewModel creates an empty model.
Model* Model :: NewModel() {
    return new Model();
}

// NewModel creates a model from a .CONF file.
Model* Model :: NewModelFromFile(string path) {
    Model* m = NewModel();
    m->LoadModel(path);
    return m;
}

// NewModel creates a model from a string which contains model text.
Model* Model :: NewModelFromString(string text) {
    Model* m = NewModel();
    m->LoadModelFromText(text);
    return m;
}

void Model :: BuildIncrementalRoleLinks(shared_ptr<RoleManager> rm, policy_op op, string sec, string p_type, vector<vector<string>> rules) {
    if (sec == "g")
        this->m[sec].assertion_map[p_type]->BuildIncrementalRoleLinks(rm, op, rules);
}

// BuildRoleLinks initializes the roles in RBAC.
void Model :: BuildRoleLinks(shared_ptr<RoleManager> rm) {
    for (unordered_map<string, shared_ptr<Assertion>> :: iterator it = this->m["g"].assertion_map.begin() ; it != this->m["g"].assertion_map.end() ; it++)
        (it->second)->BuildRoleLinks(rm);
}

// PrintPolicy prints the policy to log.
void Model :: PrintPolicy() {
    // DefaultLogger df_logger;
    // df_logger.EnableLog(true);

    // Logger *logger = &df_logger;
    // LogUtil::SetLogger(*logger);

    // LogUtil::LogPrint("Policy:");

    // for (unordered_map<string, Assertion*> :: iterator it = this->m["p"].assertion_map.begin() ; it != this->m["p"].assertion_map.end() ; it++) {
        // LogUtil::LogPrint(it->first, ": ", (it->second)->Value, ": ", (it->second)->policy);
    // }

    // for (unordered_map<string, Assertion*> :: iterator it = this->m["g"].assertion_map.begin() ; it != this->m["g"].assertion_map.end() ; it++) {
        // LogUtil::LogPrint(it->first, ": ", (it->second)->Value, ": ", (it->second)->policy);
    // }
}

// ClearPolicy clears all current policy.
void Model :: ClearPolicy() {
    for (unordered_map<string, shared_ptr<Assertion>> :: iterator it = this->m["p"].assertion_map.begin() ; it != this->m["p"].assertion_map.end() ; it++){
        if((it->second)->policy.size() > 0)
            (it->second)->policy.clear();
    }

    for (unordered_map<string, shared_ptr<Assertion>> :: iterator it = this->m["g"].assertion_map.begin() ; it != this->m["g"].assertion_map.end() ; it++){
        if((it->second)->policy.size() > 0)
            (it->second)->policy.clear();
    }
}

// GetPolicy gets all rules in a policy.
vector<vector<string>> Model :: GetPolicy(string sec, string p_type) {
    return (this->m)[sec].assertion_map[p_type]->policy;
}

// GetFilteredPolicy gets rules based on field filters from a policy.
vector<vector<string>> Model :: GetFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values) {
    vector<vector<string>> res;
    vector<vector<string>> policy(m[sec].assertion_map[p_type]->policy);
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
bool Model :: HasPolicy(string sec, string p_type, vector<string> rule) {
    vector<vector<string>> policy = m[sec].assertion_map[p_type]->policy;
    for(int i=0 ; i < policy.size() ; i++)
        if (ArrayEquals(rule, policy[i]))
            return true;

    return false;
}

// AddPolicy adds a policy rule to the model.
bool Model :: AddPolicy(string sec, string p_type, vector<string> rule) {
    if(!this->HasPolicy(sec, p_type, rule)) {
        m[sec].assertion_map[p_type]->policy.push_back(rule);
        return true;
    }

    return false;
}

// AddPolicies adds policy rules to the model.
bool Model :: AddPolicies(string sec, string p_type, vector<vector<string>> rules) {
    for (int i = 0; i < rules.size(); i++)
        if (this->HasPolicy(sec, p_type, rules[i]))
            return false;

    for (int i = 0; i < rules.size(); i++)
        this->m[sec].assertion_map[p_type]->policy.push_back(rules[i]);

    return true;
}

// RemovePolicy removes a policy rule from the model.
bool Model :: RemovePolicy(string sec, string p_type, vector<string> rule) {
    for (int i = 0 ; i < m[sec].assertion_map[p_type]->policy.size() ; i++) {
        if (ArrayEquals(rule, m[sec].assertion_map[p_type]->policy[i])) {
            m[sec].assertion_map[p_type]->policy.erase(m[sec].assertion_map[p_type]->policy.begin() + i);
            return true;
        }
    }

    return false;
}

// RemovePolicies removes policy rules from the model.
bool Model :: RemovePolicies(string sec, string p_type, vector<vector<string>> rules) {
    OUTER: for (int j = 0; j < rules.size(); j++) {
        for (int i = 0; i < this->m[sec].assertion_map[p_type]->policy.size(); i++){
            if (ArrayEquals(rules[j], this->m[sec].assertion_map[p_type]->policy[i]))
                goto OUTER;
        }
        return false;
    }

    for (int j = 0; j < rules.size(); j++){
        for (int i = 0; i < this->m[sec].assertion_map[p_type]->policy.size(); i++){
            if (ArrayEquals(rules[j], this->m[sec].assertion_map[p_type]->policy[i]))
                this->m[sec].assertion_map[p_type]->policy.erase(this->m[sec].assertion_map[p_type]->policy.begin() + i);
        }
    }

    return true;
}

// RemoveFilteredPolicy removes policy rules based on field filters from the model.
pair<bool, vector<vector<string>>> Model :: RemoveFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values) {
    vector<vector<string>> tmp;
    vector<vector<string>> effects;
    vector<vector<string>> policy(m[sec].assertion_map[p_type]->policy);
    bool res = false;
    for(int i = 0 ; i < policy.size() ; i++){
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

    m[sec].assertion_map[p_type]->policy = tmp;
    pair<bool, vector<vector<string>>> result(res, effects);
    return result;
}

// GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
vector<string> Model :: GetValuesForFieldInPolicy(string sec, string p_type, int field_index) {
    vector<string> values;
    vector<vector<string>> policy(m[sec].assertion_map[p_type]->policy);
    for(int i = 0 ; i < policy.size() ; i++)
        values.push_back((policy[i])[field_index]);

    ArrayRemoveDuplicates(values);

    return values;
}

// GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all p_types, duplicated values are removed.
vector<string> Model :: GetValuesForFieldInPolicyAllTypes(string sec, int field_index) {
    vector<string> values;

    for (unordered_map<string, shared_ptr<Assertion>> :: iterator it = m[sec].assertion_map.begin() ; it != m[sec].assertion_map.end() ; it++) {
        vector<string> values_for_field(this->GetValuesForFieldInPolicy(sec, it->first, field_index));
        for(int i = 0 ; i < values_for_field.size() ; i++)
            values.push_back(values_for_field[i]);
    }

    ArrayRemoveDuplicates(values);

    return values;
}