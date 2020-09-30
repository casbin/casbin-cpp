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

#ifndef CASBIN_CPP_ENFORCER_SYNCED
#define CASBIN_CPP_ENFORCER_SYNCED

#include <atomic>
#include <mutex>
#include <thread>

#include "./enforcer.h"
#include "./util.h"
#include "./channel.h"

class SyncedEnforcer : public Enforcer {
public:
    mutex lock;
    Channel<int> stopAutoLoad;
    atomic<int> autoLoadRunning;
    SyncedEnforcer(const SyncedEnforcer& se) = delete;
    SyncedEnforcer(SyncedEnforcer&& se);

    bool IsAutoLoadingRunning();
    void StartAutoLoadPolicy(chrono::duration<int , milli> d);
    void StopAutoLoadPolicy();
    void SetWatcher(shared_ptr<Watcher> watcher);
    void ClearPolciy();
    void LoadPolicy();
    void LoadFilteredPolicy(Filter filter);
    void LoadIncrementalFilteredPolicy(Filter filter);
    void SavePolicy();
    void BuildRoleLinks();

    bool Enforce(Scope scope);
    // Enforce with a vector param,decides whether a "subject" can access a
    // "object" with the operation "action", input parameters are usually: (sub,
    // obj, act).
    bool Enforce(vector<string> params);
    // Enforce with a map param,decides whether a "subject" can access a "object"
    // with the operation "action", input parameters are usually: (sub, obj, act).
    bool Enforce(unordered_map<string, string> params);
    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
    // access a "object" with the operation "action", input parameters are
    // usually: (matcher, sub, obj, act), use model matcher by default when
    // matcher is "".
    bool EnforceWithMatcher(string matcher, Scope scope);
    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
    // access a "object" with the operation "action", input parameters are
    // usually: (matcher, sub, obj, act), use model matcher by default when
    // matcher is "".
    bool EnforceWithMatcher(string matcher, vector<string> params);
    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
    // access a "object" with the operation "action", input parameters are
    // usually: (matcher, sub, obj, act), use model matcher by default when
    // matcher is "".
    bool EnforceWithMatcher(string matcher, unordered_map<string, string> params);

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

public:
        /*Management API member functions.*/
        vector<string> GetAllSubjects();
        vector<string> GetAllNamedSubjects(string p_type);
        vector<string> GetAllObjects();
        vector<string> GetAllNamedObjects(string p_type);
        vector<string> GetAllActions();
        vector<string> GetAllNamedActions(string p_type);
        vector<string> GetAllRoles();
        vector<string> GetAllNamedRoles(string p_type);
        vector<vector<string>> GetPolicy();
        vector<vector<string>> GetFilteredPolicy(int field_index, vector<string> field_values);
        vector<vector<string>> GetNamedPolicy(string p_type);
        vector<vector<string>> GetFilteredNamedPolicy(string p_type, int field_index, vector<string> field_values);
        vector<vector<string>> GetGroupingPolicy();
        vector<vector<string>> GetFilteredGroupingPolicy(int field_index, vector<string> field_values);
        vector<vector<string>> GetNamedGroupingPolicy(string p_type);
        vector<vector<string>> GetFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values);
        bool HasPolicy(vector<string> params);
        bool HasNamedPolicy(string p_type, vector<string> params);
        bool AddPolicy(vector<string> params);
        bool  AddPolicies(vector<vector<string>> rules);
        bool AddNamedPolicy(string p_type, vector<string> params);
        bool AddNamedPolicies(string p_type, vector<vector<string>> rules);
        bool RemovePolicy(vector<string> params);
        bool RemovePolicies(vector<vector<string>> rules);
        bool RemoveFilteredPolicy(int field_index, vector<string> field_values);
        bool RemoveNamedPolicy(string p_type, vector<string> params);
        bool RemoveNamedPolicies(string p_type, vector<vector<string>> rules);
        bool RemoveFilteredNamedPolicy(string p_type, int field_index, vector<string> field_values);
        bool HasGroupingPolicy(vector<string> params);
        bool HasNamedGroupingPolicy(string p_type, vector<string> params);
        bool AddGroupingPolicy(vector<string> params);
        bool AddGroupingPolicies(vector<vector<string>> rules);
        bool AddNamedGroupingPolicy(string p_type, vector<string> params);
        bool AddNamedGroupingPolicies(string p_type, vector<vector<string>> rules);
        bool RemoveGroupingPolicy(vector<string> params);
        bool RemoveGroupingPolicies(vector<vector<string>> rules);
        bool RemoveFilteredGroupingPolicy(int field_index, vector<string> field_values);
        bool RemoveNamedGroupingPolicy(string p_type, vector<string> params);
        bool RemoveNamedGroupingPolicies(string p_type, vector<vector<string>> rules);
        bool RemoveFilteredNamedGroupingPolicy(string p_type, int field_index, vector<string> field_values);
        void AddFunction(string name, Function function, Index nargs);
};



#endif
