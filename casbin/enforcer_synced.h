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

#ifndef CASBIN_H_ENFORCER_SYNC
#define CASBIN_H_ENFORCER_SYNC

#include <mutex>
#include <atomic>
#include <memory>

#include "./enforcer.h"
#include "./persist/watcher.h"
#include "./util/ticker.h"

namespace casbin {

class SyncedEnforcer : public Enforcer {
    std::mutex policyMutex;
    std::atomic_bool autoLoadRunning;
    std::atomic_int n;
    std::shared_ptr<Watcher> watcher;
    std::unique_ptr<Ticker> ticker;

public:
    /**
        * Enforcer is the default constructor.
    */
    SyncedEnforcer();

    /**
        * Enforcer initializes an enforcer with a model file and a policy file.
        *
        * @param model_path the path of the model file.
        * @param policy_file the path of the policy file.
    */
    SyncedEnforcer(std::string model_path, std::string policy_file);

    /**
        * Enforcer initializes an enforcer with a database adapter.
        *
        * @param model_path the path of the model file.
        * @param adapter the adapter.
    */
    SyncedEnforcer(std::string model_path, std::shared_ptr<Adapter> adapter);

    /**
        * Enforcer initializes an enforcer with a model and a database adapter.
        *
        * @param m the model.
        * @param adapter the adapter.
    */
    SyncedEnforcer(std::shared_ptr<Model> m, std::shared_ptr<Adapter> adapter);

    /**
        * Enforcer initializes an enforcer with a model.
        *
        * @param m the model.
    */
    SyncedEnforcer(std::shared_ptr<Model> m);

    /**
        * Enforcer initializes an enforcer with a model file.
        *
        * @param model_path the path of the model file.
    */
    SyncedEnforcer(std::string model_path);

    /**
        * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
        *
        * @param model_path the path of the model file.
        * @param policy_file the path of the policy file.
        * @param enable_log whether to enable Casbin's log.
    */
    SyncedEnforcer(std::string model_path, std::string policy_file, bool enable_log);

    // StartAutoLoadPolicy starts a thread that will go through every specified duration call LoadPolicy
    void StartAutoLoadPolicy(std::chrono::duration<int64_t, std::nano> t);

    // IsAutoLoadingRunning check if SyncedEnforcer is auto loading policies
    inline bool IsAutoLoadingRunning();

    // StopAutoLoadPolicy causes the thread to exit
    void StopAutoLoadPolicy();

    std::string UpdateWrapper();

    // SetWatcher sets the current watcher.
    void SetWatcher(std::shared_ptr<Watcher> w);

    // LoadModel reloads the model from the model CONF file.
    void LoadModel();

    // ClearPolicy clears all policy.
    void ClearPolicy();

    // LoadPolicy reloads the policy from file/database.
    void LoadPolicy();

    void LoadPolicyWrapper();

    // LoadFilteredPolicy reloads a filtered policy from file/database.
    template <typename Filter>
    void LoadFilteredPolicy(Filter);

    // LoadIncrementalFilteredPolicy reloads a filtered policy from file/database.
    void LoadIncrementalFilteredPolicy(Filter);

    // SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
    void SavePolicy();

    // BuildRoleLinks manually rebuild the role inheritance relations.
    void BuildRoleLinks();

    // Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
    bool Enforce(Scope);

    // Enforce with a vector param,decides whether a "subject" can access a
    // "object" with the operation "action", input parameters are usually: (sub,
    // obj, act).
    bool Enforce(std::vector<std::string> params);

    // Enforce with a map param,decides whether a "subject" can access a "object"
    // with the operation "action", input parameters are usually: (sub, obj, act).
    bool Enforce(std::unordered_map<std::string, std::string> params);

    // BatchEnforce enforce in batches
    std::vector<bool> BatchEnforce(std::vector<std::vector<std::string>> requests);

    // BatchEnforceWithMatcher enforce with matcher in batches
    std::vector<bool> BatchEnforceWithMatcher(std::string matcher, std::vector<std::vector<std::string>> requests);

    // GetAllSubjects gets the list of subjects that show up in the current policy.
    std::vector<std::string> GetAllSubjects();

    // GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
    std::vector<std::string> GetAllNamedSubjects(std::string ptype);

    // GetAllObjects gets the list of objects that show up in the current policy.
    std::vector<std::string> GetAllObjects();

    // GetAllNamedObjects gets the list of objects that show up in the current named policy.
    std::vector<std::string> GetAllNamedObjects(std::string ptype);

    // GetAllNamedActions gets the list of actions that show up in the current named policy.
    std::vector<std::string> GetAllNamedActions(std::string ptype);

    // GetAllRoles gets the list of roles that show up in the current policy.
    std::vector<std::string> GetAllRoles();

    // GetAllNamedRoles gets the list of roles that show up in the current named policy.
    std::vector<std::string> GetAllNamedRoles(std::string ptype);

    // GetPolicy gets all the authorization rules in the policy.
    std::vector<std::vector<std::string>> GetPolicy();

    // GetNamedPolicy gets all the authorization rules in the named policy.
    std::vector<std::vector<std::string>> GetNamedPolicy(std::string ptype);

    // GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
    std::vector<std::vector<std::string>> GetFilteredNamedPolicy(std::string ptype, int fieldIndex, std::vector<std::string> fieldValues);

    // GetGroupingPolicy gets all the role inheritance rules in the policy.
    std::vector<std::vector<std::string>> GetGroupingPolicy();

    // GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
    std::vector<std::vector<std::string>> GetFilteredGroupingPolicy(int fieldIndex, std::vector<std::string> fieldValues);

    // GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
    std::vector<std::vector<std::string>> GetNamedGroupingPolicy(std::string ptype);

    // GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
    std::vector<std::vector<std::string>> GetFilteredNamedGroupingPolicy(std::string ptype, int fieldIndex, std::vector<std::string> fieldValues);

    // HasPolicy determines whether an authorization rule exists.
    bool HasPolicy(std::vector<std::string> params);

    // HasNamedPolicy determines whether a named authorization rule exists.
    bool HasNamedPolicy(std::string ptype, std::vector<std::string> params);

    // AddPolicy adds an authorization rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddPolicy(std::vector<std::string> params);

    // AddPolicies adds authorization rules to the current policy.
    // If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding rule by adding the new rule.
    bool AddPolicies(std::vector<std::vector<std::string>> rules);

    // AddNamedPolicy adds an authorization rule to the current named policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddNamedPolicy(std::string ptype, std::vector<std::string> params);

    // AddNamedPolicies adds authorization rules to the current named policy.
    // If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding by adding the new rule.
    bool AddNamedPolicies(std::string ptype, std::vector<std::vector<std::string>> rules);

    // RemovePolicy removes an authorization rule from the current policy.
    bool RemovePolicy(std::vector<std::string> params);

    // UpdatePolicy updates an authorization rule from the current policy.
    bool UpdatePolicy(std::vector<std::string> oldPolicy, std::vector<std::string> newPolicy);

    bool UpdateNamedPolicy(std::string ptype, std::vector<std::string> p1, std::vector<std::string> p2);

    // UpdatePolicies updates authorization rules from the current policies.
    bool UpdatePolicies(std::vector<std::vector<std::string>> oldPolices, std::vector<std::vector<std::string>> newPolicies);

    bool UpdateNamedPolicies(std::string ptype, std::vector<std::vector<std::string>> p1, std::vector<std::vector<std::string>> p2);

    // RemovePolicies removes authorization rules from the current policy.
    bool RemovePolicies(std::vector<std::vector<std::string>> rules);

    // RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
    bool RemoveFilteredPolicy(int fieldIndex, std::vector<std::string> fieldValues);

    // RemoveNamedPolicy removes an authorization rule from the current named policy.
    bool RemoveNamedPolicy(std::string ptype, std::vector<std::string> params);

    // RemoveNamedPolicies removes authorization rules from the current named policy.
    bool RemoveNamedPolicies(std::string ptype, std::vector<std::vector<std::string>> rules);

    // RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
    bool RemoveFilteredNamedPolicy(std::string ptype, int fieldIndex, std::vector<std::string> fieldValues);

    // HasGroupingPolicy determines whether a role inheritance rule exists.
    bool HasGroupingPolicy(std::vector<std::string> params);

    // HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
    bool HasNamedGroupingPolicy(std::string ptype, std::vector<std::string> params);

    // AddGroupingPolicy adds a role inheritance rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddGroupingPolicy(std::vector<std::string> params);

    // AddGroupingPolicies adds role inheritance rulea to the current policy.
    // If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding policy rule by adding the new rule.
    bool AddGroupingPolicies(std::vector<std::vector<std::string>> rules);

    // AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddNamedGroupingPolicy(std::string ptype, std::vector<std::string> params);

    // AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
    // If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding policy rule by adding the new rule.
    bool AddNamedGroupingPolicies(std::string ptype, std::vector<std::vector<std::string>> rules);

    // RemoveGroupingPolicy removes a role inheritance rule from the current policy.
    bool RemoveGroupingPolicy(std::vector<std::string> params);

    // RemoveGroupingPolicies removes role inheritance rules from the current policy.
    bool RemoveGroupingPolicies(std::vector<std::vector<std::string>> rules);

    // RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
    bool RemoveFilteredGroupingPolicy(int fieldIndex, std::vector<std::string> fieldValues);

    // RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
    bool RemoveNamedGroupingPolicy(std::string ptype, std::vector<std::string> params);

    // RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
    bool RemoveNamedGroupingPolicies(std::string ptype, std::vector<std::vector<std::string>> rules);

    bool UpdateGroupingPolicy(std::vector<std::string> oldRule, std::vector<std::string> newRule);

    bool UpdateNamedGroupingPolicy(std::string ptype, std::vector<std::string> oldRule, std::vector<std::string> newRule);

    // RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
    bool RemoveFilteredNamedGroupingPolicy(std::string ptype, int fieldIndex, std::vector<std::string> fieldValues);

    // AddFunction adds a customized function.
    void AddFunction(std::string name, Function function, Index nargs);
};

} // namespace casbin

#endif // CASBIN_CPP_ENFORCER_SYNC
