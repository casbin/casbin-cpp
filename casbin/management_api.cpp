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

#include "./enforcer.h"

// GetAllSubjects gets the list of subjects that show up in the current policy.
vector<string> Enforcer :: GetAllSubjects() {
    return this->model->GetValuesForFieldInPolicyAllTypes("p", 0);
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedSubjects(string p_type) {
    return this->model->GetValuesForFieldInPolicy("p", p_type, 0);
}

// GetAllObjects gets the list of objects that show up in the current policy.
vector<string> Enforcer :: GetAllObjects() {
    return this->model->GetValuesForFieldInPolicyAllTypes("p", 1);
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedObjects(string p_type) {
    return this->model->GetValuesForFieldInPolicy("p", p_type, 1);
}

// GetAllActions gets the list of actions that show up in the current policy.
vector<string> Enforcer :: GetAllActions() {
    return this->model->GetValuesForFieldInPolicyAllTypes("p", 2);
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedActions(string p_type) {
    return this->model->GetValuesForFieldInPolicy("p", p_type, 2);
}

// GetAllRoles gets the list of roles that show up in the current policy.
vector<string> Enforcer :: GetAllRoles() {
    return this->model->GetValuesForFieldInPolicyAllTypes("g", 1);
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedRoles(string p_type) {
    return this->model->GetValuesForFieldInPolicy("g", p_type, 1);
}

// GetPolicy gets all the authorization rules in the policy.
vector<vector<string>> Enforcer :: GetPolicy() {
    return this->GetNamedPolicy("p");
}

// GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredPolicy(int field_index, vector<string> field_values) {
    return this->GetFilteredNamedPolicy("p", field_index, field_values);
}

// GetNamedPolicy gets all the authorization rules in the named policy.
vector<vector<string>> Enforcer :: GetNamedPolicy(string p_type) {
    return this->model->GetPolicy("p", p_type);
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredNamedPolicy(string p_type, int field_index, vector<string> field_values) {
    return this->model->GetFilteredPolicy("p", p_type, field_index, field_values);
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
vector<vector<string>> Enforcer :: GetGroupingPolicy() {
    return this->GetNamedGroupingPolicy("g");
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredGroupingPolicy(int field_index, vector<string> field_values) {
    return this->GetFilteredNamedGroupingPolicy("g", field_index, field_values);
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
vector<vector<string>> Enforcer :: GetNamedGroupingPolicy(string p_type) {
    return this->model->GetPolicy("g", p_type);
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values) {
    return this->model->GetFilteredPolicy("g", p_type, field_index, field_values);
}

// HasPolicy determines whether an authorization rule exists.
bool Enforcer :: HasPolicy(vector<string> params) {
    return this->HasNamedPolicy("p", params);
}

// HasNamedPolicy determines whether a named authorization rule exists.
bool Enforcer :: HasNamedPolicy(string p_type, vector<string> params) {
    if (params.size() == 1) {
        vector<string> str_slice{params[0]};
        return this->model->HasPolicy("p", p_type, str_slice);
    }

    vector<string> policy;
    for (int i = 0 ; i < params.size() ; i++)
        policy.push_back(params[i]);
    return this->model->HasPolicy("p", p_type, policy);
}

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddPolicy(vector<string> params) {
    return this->AddNamedPolicy("p", params);
}

// AddPolicies adds authorization rules to the current policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding rule by adding the new rule.
bool Enforcer :: AddPolicies(vector<vector<string>> rules) {
    return this->AddNamedPolicies("p", rules);
}

// AddNamedPolicy adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddNamedPolicy(string p_type, vector<string> params) {
    if (params.size() == 1) {
        vector<string> str_slice{params[0]};
        return this->addPolicy("p", p_type, str_slice);
    }

    vector<string> policy;
    for (int i = 0 ; i < params.size() ; i++)
        policy.push_back(params[i]);
    return this->addPolicy("p", p_type, policy);
}

// AddNamedPolicies adds authorization rules to the current named policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding by adding the new rule.
bool Enforcer :: AddNamedPolicies(string p_type, vector<vector<string>> rules) {
    return this->addPolicies("p", p_type, rules);
}

// RemovePolicy removes an authorization rule from the current policy.
bool Enforcer :: RemovePolicy(vector<string> params) {
    return this->RemoveNamedPolicy("p", params);
}

// RemovePolicies removes authorization rules from the current policy.
bool Enforcer :: RemovePolicies(vector<vector<string>> rules) {
    return this->RemoveNamedPolicies("p", rules);
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
bool Enforcer :: RemoveFilteredPolicy(int field_index, vector<string> field_values) {
    return this->RemoveFilteredNamedPolicy("p", field_index, field_values);
}

// RemoveNamedPolicy removes an authorization rule from the current named policy.
bool Enforcer :: RemoveNamedPolicy(string p_type, vector<string> params) {
    if (params.size() == 1) {
        vector<string> str_slice{params[0]};
        return this->removePolicy("p", p_type, str_slice);
    }

    vector<string> policy;
    for (int i = 0 ; i < params.size() ; i++)
        policy.push_back(params[i]);
    return this->removePolicy("p", p_type, policy);
}

// RemoveNamedPolicies removes authorization rules from the current named policy.
bool Enforcer :: RemoveNamedPolicies(string p_type, vector<vector<string>> rules) {
	return this->removePolicies("p", p_type, rules);
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
bool Enforcer :: RemoveFilteredNamedPolicy(string p_type, int field_index, vector<string> field_values) {
    return this->removeFilteredPolicy("p", p_type, field_index, field_values);
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
bool Enforcer :: HasGroupingPolicy(vector<string> params) {
    return this->HasNamedGroupingPolicy("g", params);
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
bool Enforcer :: HasNamedGroupingPolicy(string p_type, vector<string> params) {
    if (params.size() == 1) {
        vector<string> str_slice{params[0]};
        return this->model->HasPolicy("g", p_type, str_slice);
    }

    vector<string> policy;
    for (int i = 0 ; i < params.size() ; i++)
        policy.push_back(params[i]);
    return this->model->HasPolicy("g", p_type, policy);
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddGroupingPolicy(vector<string> params) {
    return this->AddNamedGroupingPolicy("g", params);
}

// AddGroupingPolicies adds role inheritance rulea to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
bool Enforcer :: AddGroupingPolicies(vector<vector<string>> rules) {
    return this->AddNamedGroupingPolicies("g", rules);
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddNamedGroupingPolicy(string p_type, vector<string> params) {
    bool rule_added;
    if (params.size() == 1) {
        vector<string> str_slice{params[0]};
        rule_added = this->addPolicy("g", p_type, str_slice);
    } else {
        vector<string> policy;
        for(int i = 0 ; i < params.size() ; i++)
            policy.push_back(params[i]);

        rule_added = this->addPolicy("g", p_type, policy);
    }

    if(this->auto_build_role_links)
        this->BuildRoleLinks();

    return rule_added;
}

// AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
bool Enforcer :: AddNamedGroupingPolicies(string p_type, vector<vector<string>> rules) {
    return this->addPolicies("g", p_type, rules);
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
bool Enforcer :: RemoveGroupingPolicy(vector<string> params) {
    return this->RemoveNamedGroupingPolicy("g", params);
}

// RemoveGroupingPolicies removes role inheritance rulea from the current policy.
bool Enforcer :: RemoveGroupingPolicies(vector<vector<string>> rules) {
    return this->RemoveNamedGroupingPolicies("g", rules);
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
bool Enforcer :: RemoveFilteredGroupingPolicy(int field_index, vector<string> field_values) {
    return this->RemoveFilteredNamedGroupingPolicy("g", field_index, field_values);
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
bool Enforcer :: RemoveNamedGroupingPolicy(string p_type, vector<string> params) {
    bool rule_removed;
    if(params.size() == 1){
        vector<string> str_slice{params[0]};
        rule_removed = this->removePolicy("g", p_type, str_slice);
    } else {
        vector<string> policy;
        for(int i = 0 ; i < params.size() ; i++)
            policy.push_back(params[i]);

        rule_removed = this->removePolicy("g", p_type, policy);
    }

    if(this->auto_build_role_links)
        this->BuildRoleLinks();

    return rule_removed;
}

// RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
bool Enforcer :: RemoveNamedGroupingPolicies(string p_type, vector<vector<string>> rules) {
    return this->removePolicies("g", p_type, rules);
}

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
bool Enforcer :: RemoveFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values) {
    bool rule_removed = this->removeFilteredPolicy("g", p_type, field_index, field_values);

    if(this->auto_build_role_links)
        this->BuildRoleLinks();

    return rule_removed;
}

// AddFunction adds a customized function.
void Enforcer :: AddFunction(string name, Function function, Index nargs) {
    this->func_map.AddFunction(name, function, nargs);
}