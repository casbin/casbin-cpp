#ifndef CASBIN_CPP_MODEL_POLICY
#define CASBIN_CPP_MODEL_POLICY

#include <unordered_map>
#include <string>
#include <vector>

#include "../rbac/role_manager.h"
#include "./Model.h"
// #include "../log/Logger.h"
#include "../util/array_equals.h"
#include "../util/array_remove_duplicates.h"

using namespace std;

// BuildRoleLinks initializes the roles in RBAC.
void Model::BuildRoleLinks(RoleManager* rm) {
    for (unordered_map<string, Assertion*> :: iterator it = this->m["g"].assertion_map.begin() ; it != this->m["g"].assertion_map.end() ; it++) {
        (it->second)->BuildRoleLinks(rm);
    }
}

// PrintPolicy prints the policy to log.
void Model :: PrintPolicy() {
    // DefaultLogger df_logger;
    // df_logger.EnableLog(true);

    // Logger *logger = &df_logger;
    // LogUtil::SetLogger(*logger);

    // LogUtil::LogPrint("Policy:");

    for (unordered_map<string, Assertion*> :: iterator it = this->m["p"].assertion_map.begin() ; it != this->m["p"].assertion_map.end() ; it++) {
        // LogUtil::LogPrint(it->first, ": ", (it->second)->Value, ": ", (it->second)->policy);
    }

    for (unordered_map<string, Assertion*> :: iterator it = this->m["g"].assertion_map.begin() ; it != this->m["g"].assertion_map.end() ; it++) {
        // LogUtil::LogPrint(it->first, ": ", (it->second)->Value, ": ", (it->second)->policy);
    }
}

// ClearPolicy clears all current policy.
void Model :: ClearPolicy() {
    for (unordered_map<string, Assertion*> :: iterator it = this->m["p"].assertion_map.begin() ; it != this->m["p"].assertion_map.end() ; it++) {
        (it->second)->policy.clear();
    }

    for (unordered_map<string, Assertion*> :: iterator it = this->m["g"].assertion_map.begin() ; it != this->m["g"].assertion_map.end() ; it++) {
        (it->second)->policy.clear();
    }
}

// GetPolicy gets all rules in a policy.
vector<vector<string>> Model::GetPolicy(string sec, string p_type) {
    return (this->m)[sec].assertion_map[p_type]->policy;
}

// GetFilteredPolicy gets rules based on field filters from a policy.
vector<vector<string>> Model::GetFilteredPolicy(string sec, string p_type, int field_index, vector <string> field_values) {
    vector<vector<string>> res;

    for (vector<vector<string>> :: iterator it = m[sec].assertion_map[p_type]->policy.begin() ; it != m[sec].assertion_map[p_type]->policy.end() ; it++){
        bool matched = true;
        for(int i = 0 ; i < field_values.size() ; i++){
            if(field_values[i] != "" && (*it)[field_index + i] != field_values[i] ){
                matched = false;
                break;
            }
        }
        if(matched) {
            res.push_back(*it);
        }
    }

    return res;
}

// HasPolicy determines whether a model has the specified policy rule.
bool Model::HasPolicy(string sec, string p_type, vector<string> rule) {
    for (vector<vector<string>> :: iterator it = m[sec].assertion_map[p_type]->policy.begin() ; it != m[sec].assertion_map[p_type]->policy.end() ; it++) {
        if (ArrayEquals(rule, *it)) {
            return true;
        }
    }

    return false;
}

// AddPolicy adds a policy rule to the model.
bool Model::AddPolicy(string sec, string p_type, vector<string> rule) {
    if(!this->HasPolicy(sec, p_type, rule)) {
        m[sec].assertion_map[p_type]->policy.push_back(rule);
        return true;
    }
    return false;
}

// RemovePolicy removes a policy rule from the model.
bool Model::RemovePolicy(string sec, string p_type, vector <string> rule) {
    for (int i = 0 ; i < m[sec].assertion_map[p_type]->policy.size() ; i++) {
        if (ArrayEquals(rule, m[sec].assertion_map[p_type]->policy[i])) {
            m[sec].assertion_map[p_type]->policy.erase(m[sec].assertion_map[p_type]->policy.begin() + i);
            return true;
        }
    }

    return false;
}

// RemoveFilteredPolicy removes policy rules based on field filters from the model.
bool Model::RemoveFilteredPolicy(string sec, string p_type, int field_index, vector <string> field_values) {
    vector<vector<string>> tmp;
    bool res = false;
    for (vector<vector< string>> :: iterator it = m[sec].assertion_map[p_type]->policy.begin() ; it != m[sec].assertion_map[p_type]->policy.end() ; it++) {
        bool matched = true;
        for (int i = 0 ; i < field_values.size() ; i++) {
            if (field_values[i] != "" && (*it)[field_index+i] != field_values[i]) {
                matched = false;
                break;
            }
        }
        if (matched) {
            res = true;
        } else {
            tmp.push_back(*it);
        }
    }

    m[sec].assertion_map[p_type]->policy = tmp;
    return res;
}

// GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
vector<string> Model::GetValuesForFieldInPolicy(string sec, string p_type, int field_index) {
    vector<string> values;

    for (vector<vector<string>> :: iterator it = m[sec].assertion_map[p_type]->policy.begin() ; it != m[sec].assertion_map[p_type]->policy.end() ; it++){
        values.push_back((*it)[field_index]);
    }

    ArrayRemoveDuplicates(values);

    return values;
}

// GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all p_types, duplicated values are removed.
vector<string> Model::GetValuesForFieldInPolicyAllTypes(string sec, int field_index) {
    vector<string> values;

    for (unordered_map<string, Assertion*> :: iterator it = m[sec].assertion_map.begin() ; it != m[sec].assertion_map.end() ; it++) {
        for (vector<string> :: iterator it1 = this->GetValuesForFieldInPolicy(sec, it->first, field_index).begin() ; it1 != this->GetValuesForFieldInPolicy(sec, it->first, field_index).end() ; it1++) {
            values.push_back(*it1);
        }
    }

    ArrayRemoveDuplicates(values);

    return values;
}

#endif