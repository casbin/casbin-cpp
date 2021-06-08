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

namespace casbin {

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
class AssertionMap {
    public:

        std::unordered_map<std::string, std::shared_ptr<Assertion>> assertion_map;
};

// Model represents the whole access control model.
class Model{
    private:

        static std::unordered_map<std::string, std::string> section_name_map;

        static void LoadSection(Model* model, std::shared_ptr<ConfigInterface> cfg, std::string sec);

        static std::string GetKeySuffix(int i);

        static bool LoadAssertion(Model* model, std::shared_ptr<ConfigInterface> cfg, std::string sec, std::string key);

    public:

        Model();

        Model(std::string path);

        std::unordered_map<std::string, AssertionMap> m;

        // Minimal required sections for a model to be valid
        static std::vector<std::string> required_sections;

        bool HasSection(std::string sec);

        // AddDef adds an assertion to the model.
        bool AddDef(std::string sec, std::string key, std::string value);

        // LoadModel loads the model from model CONF file.
        void LoadModel(std::string path);

        // LoadModelFromText loads the model from the text.
        void LoadModelFromText(std::string text);

        void LoadModelFromConfig(std::shared_ptr<ConfigInterface> cfg);

        // PrintModel prints the model to the log.
        void PrintModel();

        // NewModel creates an empty model.
        static Model* NewModel();

        // NewModel creates a model from a .CONF file.
        static Model* NewModelFromFile(std::string path);

        // NewModel creates a model from a std::string which contains model text.
        static Model* NewModelFromString(std::string text);

        void BuildIncrementalRoleLinks(std::shared_ptr<RoleManager> rm, policy_op op, std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules);

        // BuildRoleLinks initializes the roles in RBAC.
        void BuildRoleLinks(std::shared_ptr<RoleManager> rm);

        // PrintPolicy prints the policy to log.
        void PrintPolicy();

        // ClearPolicy clears all current policy.
        void ClearPolicy();

        // GetPolicy gets all rules in a policy.
        std::vector<std::vector<std::string>> GetPolicy(std::string sec, std::string p_type);

        // GetFilteredPolicy gets rules based on field filters from a policy.
        std::vector<std::vector<std::string>> GetFilteredPolicy(std::string sec, std::string p_type, int field_index, std::vector<std::string> field_values);

        // HasPolicy determines whether a model has the specified policy rule.
        bool HasPolicy(std::string sec, std::string p_type, std::vector<std::string> rule);

        // AddPolicy adds a policy rule to the model.
        bool AddPolicy(std::string sec, std::string p_type, std::vector<std::string> rule);

        // AddPolicies adds policy rules to the model.
        bool AddPolicies(std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules);

        // UpdatePolicy updates a policy rule from the model.
        bool UpdatePolicy(const std::string& sec, const std::string p_type, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule);

        // RemovePolicy removes a policy rule from the model.
        bool RemovePolicy(std::string sec, std::string p_type, std::vector<std::string> rule);

        // RemovePolicies removes policy rules from the model.
        bool RemovePolicies(std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules);

        // RemoveFilteredPolicy removes policy rules based on field filters from the model.
        std::pair<bool, std::vector<std::vector<std::string>>> RemoveFilteredPolicy(std::string sec, std::string p_type, int field_index, std::vector<std::string> field_values);

        // GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
        std::vector<std::string> GetValuesForFieldInPolicy(std::string sec, std::string p_type, int field_index);

        // GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all p_types, duplicated values are removed.
        std::vector<std::string> GetValuesForFieldInPolicyAllTypes(std::string sec, int field_index);
};

};  // namespace casbin

#endif