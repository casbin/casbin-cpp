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

class SyncedEnforcer : public Enforcer {
    mutex policyMutex;
    atomic_bool autoLoadRunning;
    atomic_int n;
    shared_ptr<Watcher> watcher;
    unique_ptr<Ticker> ticker;

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
    SyncedEnforcer(string model_path, string policy_file);

    /**
        * Enforcer initializes an enforcer with a database adapter.
        *
        * @param model_path the path of the model file.
        * @param adapter the adapter.
    */
    SyncedEnforcer(string model_path, shared_ptr<Adapter> adapter);

    /**
        * Enforcer initializes an enforcer with a model and a database adapter.
        *
        * @param m the model.
        * @param adapter the adapter.
    */
    SyncedEnforcer(shared_ptr<Model> m, shared_ptr<Adapter> adapter);

    /**
        * Enforcer initializes an enforcer with a model.
        *
        * @param m the model.
    */
    SyncedEnforcer(shared_ptr<Model> m);

    /**
        * Enforcer initializes an enforcer with a model file.
        *
        * @param model_path the path of the model file.
    */
    SyncedEnforcer(string model_path);

    /**
        * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
        *
        * @param model_path the path of the model file.
        * @param policy_file the path of the policy file.
        * @param enable_log whether to enable Casbin's log.
    */
    SyncedEnforcer(string model_path, string policy_file, bool enable_log);

    // StartAutoLoadPolicy starts a thread that will go through every specified duration call LoadPolicy
    void StartAutoLoadPolicy(std::chrono::duration<int64_t, std::nano> t);

    // IsAutoLoadingRunning check if SyncedEnforcer is auto loading policies
    inline bool IsAutoLoadingRunning();

    // StopAutoLoadPolicy causes the thread to exit
    void StopAutoLoadPolicy();

    string UpdateWrapper();

    // SetWatcher sets the current watcher.
    void SetWatcher(shared_ptr<Watcher> w);

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
    bool Enforce(vector<string> params);

    // Enforce with a map param,decides whether a "subject" can access a "object"
    // with the operation "action", input parameters are usually: (sub, obj, act).
    bool Enforce(unordered_map<string, string> params);

    // BatchEnforce enforce in batches
    vector<bool> BatchEnforce(vector<vector<string>> requests);

    // BatchEnforceWithMatcher enforce with matcher in batches
    vector<bool> BatchEnforceWithMatcher(string matcher, vector<vector<string>> requests);

    // GetAllSubjects gets the list of subjects that show up in the current policy.
    vector<string> GetAllSubjects();

    // GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
    vector<string> GetAllNamedSubjects(string ptype);

    // GetAllObjects gets the list of objects that show up in the current policy.
    vector<string> GetAllObjects();

    // GetAllNamedObjects gets the list of objects that show up in the current named policy.
    vector<string> GetAllNamedObjects(string ptype);

    // GetAllNamedActions gets the list of actions that show up in the current named policy.
    vector<string> GetAllNamedActions(string ptype);

    // GetAllRoles gets the list of roles that show up in the current policy.
    vector<string> GetAllRoles();

    // GetAllNamedRoles gets the list of roles that show up in the current named policy.
    vector<string> GetAllNamedRoles(string ptype);

    // GetPolicy gets all the authorization rules in the policy.
    vector<vector<string>> GetPolicy();

    // GetNamedPolicy gets all the authorization rules in the named policy.
    vector<vector<string>> GetNamedPolicy(string ptype);

    // GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
    vector<vector<string>> GetFilteredNamedPolicy(string ptype, int fieldIndex, vector<string> fieldValues);

    // GetGroupingPolicy gets all the role inheritance rules in the policy.
    vector<vector<string>> GetGroupingPolicy();

    // GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
    vector<vector<string>> GetFilteredGroupingPolicy(int fieldIndex, vector<string> fieldValues);

    // GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
    vector<vector<string>> GetNamedGroupingPolicy(string ptype);

    // GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
    vector<vector<string>> GetFilteredNamedGroupingPolicy(string ptype, int fieldIndex, vector<string> fieldValues);

    // HasPolicy determines whether an authorization rule exists.
    bool HasPolicy(vector<string> params);

    // HasNamedPolicy determines whether a named authorization rule exists.
    bool HasNamedPolicy(string ptype, vector<string> params);

    // AddPolicy adds an authorization rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddPolicy(vector<string> params);

    // AddPolicies adds authorization rules to the current policy.
    // If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding rule by adding the new rule.
    bool AddPolicies(vector<vector<string>> rules);

    // AddNamedPolicy adds an authorization rule to the current named policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddNamedPolicy(string ptype, vector<string> params);

    // AddNamedPolicies adds authorization rules to the current named policy.
    // If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding by adding the new rule.
    bool AddNamedPolicies(string ptype, vector<vector<string>> rules);

    // RemovePolicy removes an authorization rule from the current policy.
    bool RemovePolicy(vector<string> params);

    // UpdatePolicy updates an authorization rule from the current policy.
    bool UpdatePolicy(vector<string> oldPolicy, vector<string> newPolicy);

    bool UpdateNamedPolicy(string ptype, vector<string> p1, vector<string> p2);

    // UpdatePolicies updates authorization rules from the current policies.
    bool UpdatePolicies(vector<vector<string>> oldPolices, vector<vector<string>> newPolicies);

    bool UpdateNamedPolicies(string ptype, vector<vector<string>> p1, vector<vector<string>> p2);

    // RemovePolicies removes authorization rules from the current policy.
    bool RemovePolicies(vector<vector<string>> rules);

    // RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
    bool RemoveFilteredPolicy(int fieldIndex, vector<string> fieldValues);

    // RemoveNamedPolicy removes an authorization rule from the current named policy.
    bool RemoveNamedPolicy(string ptype, vector<string> params);

    // RemoveNamedPolicies removes authorization rules from the current named policy.
    bool RemoveNamedPolicies(string ptype, vector<vector<string>> rules);

    // RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
    bool RemoveFilteredNamedPolicy(string ptype, int fieldIndex, vector<string> fieldValues);

    // HasGroupingPolicy determines whether a role inheritance rule exists.
    bool HasGroupingPolicy(vector<string> params);

    // HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
    bool HasNamedGroupingPolicy(string ptype, vector<string> params);

    // AddGroupingPolicy adds a role inheritance rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddGroupingPolicy(vector<string> params);

    // AddGroupingPolicies adds role inheritance rulea to the current policy.
    // If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding policy rule by adding the new rule.
    bool AddGroupingPolicies(vector<vector<string>> rules);

    // AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
    // If the rule already exists, the function returns false and the rule will not be added.
    // Otherwise the function returns true by adding the new rule.
    bool AddNamedGroupingPolicy(string ptype, vector<string> params);

    // AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
    // If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
    // Otherwise the function returns true for the corresponding policy rule by adding the new rule.
    bool AddNamedGroupingPolicies(string ptype, vector<vector<string>> rules);

    // RemoveGroupingPolicy removes a role inheritance rule from the current policy.
    bool RemoveGroupingPolicy(vector<string> params);

    // RemoveGroupingPolicies removes role inheritance rules from the current policy.
    bool RemoveGroupingPolicies(vector<vector<string>> rules);

    // RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
    bool RemoveFilteredGroupingPolicy(int fieldIndex, vector<string> fieldValues);

    // RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
    bool RemoveNamedGroupingPolicy(string ptype, vector<string> params);

    // RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
    bool RemoveNamedGroupingPolicies(string ptype, vector<vector<string>> rules);

    bool UpdateGroupingPolicy(vector<string> oldRule, vector<string> newRule);

    bool UpdateNamedGroupingPolicy(string ptype, vector<string> oldRule, vector<string> newRule);

    // RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
    bool RemoveFilteredNamedGroupingPolicy(string ptype, int fieldIndex, vector<string> fieldValues);

    // AddFunction adds a customized function.
    void AddFunction(string name, Function function, Index nargs);
};

#endif // CASBIN_CPP_ENFORCER_SYNC
