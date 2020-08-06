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

#ifndef CASBIN_CPP_MODEL_MODEL
#define CASBIN_CPP_MODEL_MODEL

#include <unordered_map>

#include "./assertion.h"
#include "../config/config_interface.h"

using namespace std;

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
class AssertionMap {
    public:

        unordered_map<string, shared_ptr<Assertion>> assertion_map;
};

// Model represents the whole access control model.
class Model{
    private:

        static unordered_map<string, string> section_name_map;

        static void LoadSection(Model* model, shared_ptr<ConfigInterface> cfg, string sec);

        static string GetKeySuffix(int i);

        static bool LoadAssertion(Model* model, shared_ptr<ConfigInterface> cfg, string sec, string key);

    public:

        Model();

        Model(string path);

        unordered_map<string, AssertionMap> m;

        // Minimal required sections for a model to be valid
        static vector<string> required_sections;

        bool HasSection(string sec);

        // AddDef adds an assertion to the model.
        bool AddDef(string sec, string key, string value);

        // LoadModel loads the model from model CONF file.
        void LoadModel(string path);

        // LoadModelFromText loads the model from the text.
        void LoadModelFromText(string text);

        void LoadModelFromConfig(shared_ptr<ConfigInterface> cfg);

        // PrintModel prints the model to the log.
        void PrintModel();

        // NewModel creates an empty model.
        static Model* NewModel();

        // NewModel creates a model from a .CONF file.
        static Model* NewModelFromFile(string path);

        // NewModel creates a model from a string which contains model text.
        static Model* NewModelFromString(string text);

        void BuildIncrementalRoleLinks(shared_ptr<RoleManager> rm, policy_op op, string sec, string p_type, vector<vector<string>> rules);

        // BuildRoleLinks initializes the roles in RBAC.
        void BuildRoleLinks(shared_ptr<RoleManager> rm);

        // PrintPolicy prints the policy to log.
        void PrintPolicy();

        // ClearPolicy clears all current policy.
        void ClearPolicy();

        // GetPolicy gets all rules in a policy.
        vector<vector<string>> GetPolicy(string sec, string p_type);

        // GetFilteredPolicy gets rules based on field filters from a policy.
        vector<vector<string>> GetFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values);

        // HasPolicy determines whether a model has the specified policy rule.
        bool HasPolicy(string sec, string p_type, vector<string> rule);

        // AddPolicy adds a policy rule to the model.
        bool AddPolicy(string sec, string p_type, vector<string> rule);

        // AddPolicies adds policy rules to the model.
        bool AddPolicies(string sec, string p_type, vector<vector<string>> rules);

        // RemovePolicy removes a policy rule from the model.
        bool RemovePolicy(string sec, string p_type, vector<string> rule);

        // RemovePolicies removes policy rules from the model.
        bool RemovePolicies(string sec, string p_type, vector<vector<string>> rules);

        // RemoveFilteredPolicy removes policy rules based on field filters from the model.
        pair<bool, vector<vector<string>>> RemoveFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values);

        // GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
        vector<string> GetValuesForFieldInPolicy(string sec, string p_type, int field_index);

        // GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all p_types, duplicated values are removed.
        vector<string> GetValuesForFieldInPolicyAllTypes(string sec, int field_index);
};

#endif