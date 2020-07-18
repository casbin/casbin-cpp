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

#ifndef CASBIN_CPP_ENFORCER
#define CASBIN_CPP_ENFORCER

#include<memory>
#include "./rbac/role_manager.h"
#include "./model/function.h"
#include "./enforcer_interface.h"
#include "./persist/filtered_adapter.h"

// Enforcer is the main interface for authorization enforcement and policy management.
class Enforcer : public IEnforcer{
    private:

        string model_path;
        shared_ptr<Model> model;
        FunctionMap func_map;
        shared_ptr<Effector> eft;

        shared_ptr<Adapter> adapter;
        shared_ptr<Watcher> watcher;

        bool enabled;
        bool auto_save;
        bool auto_build_role_links;
        bool auto_notify_watcher;

        // enforce use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool enforce(string matcher, Scope scope);

    public:

        shared_ptr<RoleManager> rm;

        /**
         * Enforcer is the default constructor.
         */
        static unique_ptr<Enforcer> NewEnforcer();
        /**
         * Enforcer initializes an enforcer with a model file and a policy file.
         *
         * @param model_path the path of the model file.
         * @param policyFile the path of the policy file.
         */
        static unique_ptr<Enforcer> NewEnforcer(string model_path, string policyFile);
        /**
         * Enforcer initializes an enforcer with a database adapter.
         *
         * @param model_path the path of the model file.
         * @param adapter the adapter.
         */
        static unique_ptr<Enforcer> NewEnforcer(string model_path, shared_ptr<Adapter> adapter);
        /**
         * Enforcer initializes an enforcer with a model and a database adapter.
         *
         * @param m the model.
         * @param adapter the adapter.
         */
        static unique_ptr<Enforcer> NewEnforcer(shared_ptr<Model> m, shared_ptr<Adapter> adapter);
        /**
         * Enforcer initializes an enforcer with a model.
         *
         * @param m the model.
         */
        static unique_ptr<Enforcer> NewEnforcer(shared_ptr<Model> m);
        /**
         * Enforcer initializes an enforcer with a model file.
         *
         * @param model_path the path of the model file.
         */
        static unique_ptr<Enforcer> NewEnforcer(string model_path);
        /**
         * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
         *
         * @param model_path the path of the model file.
         * @param policyFile the path of the policy file.
         * @param enableLog whether to enable Casbin's log.
         */
        static unique_ptr<Enforcer> NewEnforcer(string model_path, string policyFile, bool enableLog);
        // InitWithFile initializes an enforcer with a model file and a policy file.
        void InitWithFile(string model_path, string policyPath);
        // InitWithAdapter initializes an enforcer with a database adapter.
        void InitWithAdapter(string model_path, shared_ptr<Adapter> adapter);
        // InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
        void InitWithModelAndAdapter(shared_ptr<Model> m, shared_ptr<Adapter> adapter);
        void Initialize();
        // LoadModel reloads the model from the model CONF file.
        // Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
        void LoadModel();
        // GetModel gets the current model.
        shared_ptr<Model> GetModel();
        // SetModel sets the current model.
        void SetModel(shared_ptr<Model> m);
        // GetAdapter gets the current adapter.
        shared_ptr<Adapter> GetAdapter();
        // SetAdapter sets the current adapter.
        void SetAdapter(shared_ptr<Adapter> adapter);
        // SetWatcher sets the current watcher.
        void SetWatcher(shared_ptr<Watcher> watcher);
        // GetRoleManager gets the current role manager.
        shared_ptr<RoleManager> GetRoleManager();
        // SetRoleManager sets the current role manager.
        void SetRoleManager(shared_ptr <RoleManager> rm);
        // SetEffector sets the current effector.
        void SetEffector(shared_ptr<Effector> eft);
        // ClearPolicy clears all policy.
        void ClearPolicy();
        // LoadPolicy reloads the policy from file/database.
        void LoadPolicy();
        //LoadFilteredPolicy reloads a filtered policy from file/database.
        template<typename Filter>
        void LoadFilteredPolicy(Filter filter);
        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered();
        // SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
        void SavePolicy();
        // EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
        void EnableEnforce(bool enable);
        // EnableLog changes whether Casbin will log messages to the Logger.
        // void EnableLog(bool enable) {
            // log.GetLogger().EnableLog(enable);
        // }

        // EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
        void EnableAutoNotifyWatcher(bool enable);
        // EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
        void EnableAutoSave(bool auto_save);
        // EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
        void EnableAutoBuildRoleLinks(bool auto_build_role_links);
        // BuildRoleLinks manually rebuild the role inheritance relations.
        void BuildRoleLinks();
        // BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
        void BuildIncrementalRoleLinks(policy_op op, string p_type, vector<vector<string>> rules);
        // Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(Scope scope);
        // Enforce with a vector param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(vector<string> params);        
        // Enforce with a map param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(unordered_map<string,string> params);
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(string matcher, Scope scope);
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(string matcher, vector<string> params);
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(string matcher, unordered_map<string, string> params);
       
        /*Management API member functions.*/
        vector<string> GetAllSubjects();
        vector<string> GetAllNamedSubjects(string ptype);
        vector<string> GetAllObjects();
        vector<string> GetAllNamedObjects(string ptype);
        vector<string> GetAllActions();
        vector<string> GetAllNamedActions(string ptype);
        vector<string> GetAllRoles();
        vector<string> GetAllNamedRoles(string ptype);
        vector<vector<string>> GetPolicy();
        vector<vector<string>> GetFilteredPolicy(int field_index, vector<string> field_values);
        vector<vector<string>> GetNamedPolicy(string ptype);
        vector<vector<string>> GetFilteredNamedPolicy(string ptype, int field_index, vector<string> field_values);
        vector<vector<string>> GetGroupingPolicy();
        vector<vector<string>> GetFilteredGroupingPolicy(int field_index, vector<string> field_values);
        vector<vector<string>> GetNamedGroupingPolicy(string ptype);
        vector<vector<string>> GetFilteredNamedGroupingPolicy(string ptype, int field_index, vector<string> field_values);
        bool HasPolicy(vector<string> params);
        bool HasNamedPolicy(string ptype, vector<string> params);
        bool AddPolicy(vector<string> params);
        bool  AddPolicies(vector<vector<string>> rules);
        bool AddNamedPolicy(string ptype, vector<string> params);
        bool AddNamedPolicies(string p_type, vector<vector<string>> rules);
        bool RemovePolicy(vector<string> params);
        bool RemovePolicies(vector<vector<string>> rules);
        bool RemoveFilteredPolicy(int field_index, vector<string> field_values);
        bool RemoveNamedPolicy(string ptype, vector<string> params);
        bool RemoveNamedPolicies(string p_type, vector<vector<string>> rules);
        bool RemoveFilteredNamedPolicy(string ptype, int field_index, vector<string> field_values);
        bool HasGroupingPolicy(vector<string> params);
        bool HasNamedGroupingPolicy(string ptype, vector<string> params);
        bool AddGroupingPolicy(vector<string> params);
        bool AddGroupingPolicies(vector<vector<string>> rules);
        bool AddNamedGroupingPolicy(string ptype, vector<string> params);
        bool AddNamedGroupingPolicies(string p_type, vector<vector<string>> rules);
        bool RemoveGroupingPolicy(vector<string> params);
        bool RemoveGroupingPolicies(vector<vector<string>> rules);
        bool RemoveFilteredGroupingPolicy(int field_index, vector<string> field_values);
        bool RemoveNamedGroupingPolicy(string ptype, vector<string> params);
        bool RemoveNamedGroupingPolicies(string p_type, vector<vector<string>> rules);
        bool RemoveFilteredNamedGroupingPolicy(string ptype, int field_index, vector<string> field_values);
        void AddFunction(string name, Function function, Index nargs);

        /*RBAC API member functions.*/
        vector<string> GetRolesForUser(string name, vector<string> domain = {});
        vector<string> GetUsersForRole(string name, vector<string> domain = {});
        bool HasRoleForUser(string name, string role);
        bool AddRoleForUser(string user, string role);
        bool AddRolesForUser(string user, vector<string> roles);
        bool AddPermissionForUser(string user, vector<string> permission);
        bool DeletePermissionForUser(string user, vector<string> permission);
        bool DeletePermissionsForUser(string user);
        vector<vector<string>> GetPermissionsForUser(string user);
        bool HasPermissionForUser(string user, vector<string> permission);
        vector<string> GetImplicitRolesForUser(string name, vector<string> domain = {});
        vector<vector<string>> GetImplicitPermissionsForUser(string user, vector<string> domain = {});
        vector<string> GetImplicitUsersForPermission(vector<string> permission);
        bool DeleteRoleForUser(string user, string role);
        bool DeleteRolesForUser(string user);
        bool DeleteUser(string user);
        bool DeleteRole(string role);
        bool DeletePermission(vector<string> permission);

        /* Internal API member functions */
        bool addPolicy(string sec, string ptype, vector<string> rule);
        bool addPolicies(string sec, string p_type, vector<vector<string>> rules);
        bool removePolicy(string sec , string ptype , vector<string> rule);
        bool removePolicies(string sec, string p_type, vector<vector<string>> rules);
        bool removeFilteredPolicy(string sec , string ptype , int fieldIndex , vector<string> fieldValues);

        /* RBAC API with domains.*/
        vector<string> GetUsersForRoleInDomain(string name, string domain = {});
        vector<string> GetRolesForUserInDomain(string name, string domain = {});
        vector<vector<string>> GetPermissionsForUserInDomain(string user, string domain = {});
        bool AddRoleForUserInDomain(string user, string role, string domain = {});
        bool DeleteRoleForUserInDomain(string user, string role, string domain = {});

};

#endif