#ifndef CASBIN_CPP_MANAGEMENT_API
#define CASBIN_CPP_MANAGEMENT_API

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

// RemovePolicy removes an authorization rule from the current policy.
bool Enforcer :: RemovePolicy(vector<string> params) {
    return this->RemoveNamedPolicy("p", params);
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

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
bool Enforcer :: RemoveGroupingPolicy(vector<string> params) {
    return this->RemoveNamedGroupingPolicy("g", params);
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

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
bool Enforcer :: RemoveFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values) {
    bool rule_removed = this->removeFilteredPolicy("g", p_type, field_index, field_values);

    if(this->auto_build_role_links)
        this->BuildRoleLinks();

    return rule_removed;
}

// AddFunction adds a customized function.
void Enforcer :: AddFunction(string name, Function function) {
    this->func_map.AddFunction(name, function);
}

#endif