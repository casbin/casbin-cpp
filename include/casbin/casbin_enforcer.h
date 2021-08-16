/*
* Copyright 2021 The casbin Authors. All Rights Reserved.
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
*
* This is the main file for python bindings workflow
*/

#ifndef CASBIN_CPP_ENFORCER_H
#define CASBIN_CPP_ENFORCER_H

#include "casbin_helpers.h"

namespace casbin {

    // IEnforcer is the API interface of Enforcer
    class IEnforcer {
    public:

        /* Enforcer API */
        virtual void InitWithFile(const std::string& model_path, const std::string& policy_path) = 0;
        virtual void InitWithAdapter(const std::string& model_path, std::shared_ptr<Adapter> adapter) = 0;
        virtual void InitWithModelAndAdapter(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter) = 0;
        virtual void Initialize() = 0;
        virtual void LoadModel() = 0;
        virtual std::shared_ptr<Model> GetModel() = 0;
        virtual void SetModel(const std::shared_ptr<Model>& m) = 0;
        virtual std::shared_ptr<Adapter> GetAdapter() = 0;
        virtual void SetAdapter(std::shared_ptr<Adapter> adapter) = 0;
        virtual void SetWatcher(std::shared_ptr<Watcher> watcher) = 0;
        virtual std::shared_ptr<RoleManager> GetRoleManager() = 0;
        virtual void SetRoleManager(std::shared_ptr<RoleManager>& rm) = 0;
        virtual void SetEffector(std::shared_ptr<Effector> eft) = 0;
        virtual void ClearPolicy() = 0;
        virtual void LoadPolicy() = 0;

        template<typename Filter>
        void LoadFilteredPolicy(Filter filter);

        virtual bool IsFiltered() = 0;
        virtual void SavePolicy() = 0;
        virtual void EnableEnforce(bool enable) = 0;
        // virtual void EnableLog(bool enable) = 0;
        virtual void EnableAutoNotifyWatcher(bool enable) = 0;
        virtual void EnableAutoSave(bool auto_save) = 0;
        virtual void EnableAutoBuildRoleLinks(bool auto_build_role_links) = 0;
        virtual void BuildRoleLinks() = 0;
        virtual bool m_enforce(const std::string& matcher, Scope scope) = 0;
        virtual bool Enforce(Scope scope) = 0;
        virtual bool EnforceWithMatcher(const std::string& matcher, Scope scope) = 0;
        virtual std::vector<bool> BatchEnforce(const std::initializer_list<DataList>& requests) = 0;
        virtual std::vector<bool> BatchEnforceWithMatcher(const std::string& matcher, const std::initializer_list<DataList>& requests) = 0;

        /* RBAC API */
        virtual std::vector<std::string> GetRolesForUser(const std::string& name, const std::vector<std::string>& domain = {}) = 0;
        virtual std::vector<std::string> GetUsersForRole(const std::string& name, const std::vector<std::string>& domain = {}) = 0;
        virtual bool HasRoleForUser(const std::string& name, const std::string& role) = 0;
        virtual bool AddRoleForUser(const std::string& user, const std::string& role) = 0;
        virtual bool AddRolesForUser(const std::string& user, const std::vector<std::string>& roles) = 0;
        virtual bool AddPermissionForUser(const std::string& user, const std::vector<std::string>& permission) = 0;
        virtual bool DeletePermissionForUser(const std::string& user, const std::vector<std::string>& permission) = 0;
        virtual bool DeletePermissionsForUser(const std::string& user) = 0;
        virtual std::vector<std::vector<std::string>> GetPermissionsForUser(const std::string& user) = 0;
        virtual bool HasPermissionForUser(const std::string& user, const std::vector<std::string>& permission) = 0;
        virtual std::vector<std::string> GetImplicitRolesForUser(const std::string& name, const std::vector<std::string>& domain = {}) = 0;
        virtual std::vector<std::vector<std::string>> GetImplicitPermissionsForUser(const std::string& user, const std::vector<std::string>& domain = {}) = 0;
        virtual std::vector<std::string> GetImplicitUsersForPermission(const std::vector<std::string>& permission) = 0;
        virtual bool DeleteRoleForUser(const std::string& user, const std::string& role) = 0;
        virtual bool DeleteRolesForUser(const std::string& user) = 0;
        virtual bool DeleteUser(const std::string& user) = 0;
        virtual bool DeleteRole(const std::string& role) = 0;
        virtual bool DeletePermission(const std::vector<std::string>& permission) = 0;

        /* Management API */
        virtual std::vector<std::string> GetAllSubjects() = 0;
        virtual std::vector<std::string> GetAllNamedSubjects(const std::string& p_type) = 0;
        virtual std::vector<std::string> GetAllObjects() = 0;
        virtual std::vector<std::string> GetAllNamedObjects(const std::string& p_type) = 0;
        virtual std::vector<std::string> GetAllActions() = 0;
        virtual std::vector<std::string> GetAllNamedActions(const std::string& p_type) = 0;
        virtual std::vector<std::string> GetAllRoles() = 0;
        virtual std::vector<std::string> GetAllNamedRoles(const std::string& p_type) = 0;
        virtual std::vector<std::vector<std::string>> GetPolicy() = 0;
        virtual std::vector<std::vector<std::string>> GetFilteredPolicy(int field_index, const std::vector<std::string>& field_values) = 0;
        virtual std::vector<std::vector<std::string>> GetNamedPolicy(const std::string& p_type) = 0;
        virtual std::vector<std::vector<std::string>> GetFilteredNamedPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) = 0;
        virtual std::vector<std::vector<std::string>> GetGroupingPolicy() = 0;
        virtual std::vector<std::vector<std::string>> GetFilteredGroupingPolicy(int field_index, const std::vector<std::string>& field_values) = 0;
        virtual std::vector<std::vector<std::string>> GetNamedGroupingPolicy(const std::string& p_type) = 0;
        virtual std::vector<std::vector<std::string>> GetFilteredNamedGroupingPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) = 0;
        virtual bool HasPolicy(const std::vector<std::string>& params) = 0;
        virtual bool HasNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
        virtual bool AddPolicy(const std::vector<std::string>& params) = 0;
        virtual bool  AddPolicies(const std::vector<std::vector<std::string>>& rules) = 0;
        virtual bool AddNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
        virtual bool AddNamedPolicies(const std::string& p_type, const std::vector<std::vector<std::string>>& rules) = 0;
        virtual bool RemovePolicy(const std::vector<std::string>& params) = 0;
        virtual bool RemovePolicies(const std::vector<std::vector<std::string>>& rules) = 0;
        virtual bool RemoveFilteredPolicy(int field_index, const std::vector<std::string>& field_values) = 0;
        virtual bool RemoveNamedPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
        virtual bool RemoveNamedPolicies(const std::string& p_type, const std::vector<std::vector<std::string>>& rules) = 0;
        virtual bool RemoveFilteredNamedPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) = 0;
        virtual bool HasGroupingPolicy(const std::vector<std::string>& params) = 0;
        virtual bool HasNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
        virtual bool AddGroupingPolicy(const std::vector<std::string>& params) = 0;
        virtual bool AddGroupingPolicies(const std::vector<std::vector<std::string>>& rules) = 0;
        virtual bool AddNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
        virtual bool AddNamedGroupingPolicies(const std::string& p_type, const std::vector<std::vector<std::string>>& rules) = 0;
        virtual bool RemoveGroupingPolicy(const std::vector<std::string>& params) = 0;
        virtual bool RemoveGroupingPolicies(const std::vector<std::vector<std::string>>& rules) = 0;
        virtual bool RemoveFilteredGroupingPolicy(int field_index, const std::vector<std::string>& field_values) = 0;
        virtual bool RemoveNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params) = 0;
        virtual bool RemoveNamedGroupingPolicies(const std::string& p_type, const std::vector<std::vector<std::string>>& rules) = 0;
        virtual bool RemoveFilteredNamedGroupingPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values) = 0;
        virtual void AddFunction(const std::string& name, Function function, Index nargs) = 0;
        virtual bool UpdateGroupingPolicy(const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) = 0;
        virtual bool UpdateNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) = 0;
        virtual bool UpdatePolicy(const std::vector<std::string>& oldPolicy, const std::vector<std::string>& newPolicy) = 0;
        virtual bool UpdateNamedPolicy(const std::string& ptype, const std::vector<std::string>& p1, const std::vector<std::string>& p2) = 0;
        virtual bool UpdatePolicies(const std::vector<std::vector<std::string>>& oldPolices, const std::vector<std::vector<std::string>>& newPolicies) = 0;
        virtual bool UpdateNamedPolicies(const std::string& ptype, const std::vector<std::vector<std::string>>& p1, const std::vector<std::vector<std::string>>& p2) = 0;

        /* Internal API member functions */
        virtual bool addPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule) = 0;
        virtual bool addPolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules) = 0;
        virtual bool removePolicy(const std::string& sec , const std::string& p_type , const std::vector<std::string>& rule) = 0;
        virtual bool removePolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules) = 0;
        virtual bool removeFilteredPolicy(const std::string& sec , const std::string& p_type , int field_index , const std::vector<std::string>& field_values) = 0;
        virtual bool updatePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule) = 0;
        virtual bool updatePolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& p1, const std::vector<std::vector<std::string>>& p2) = 0;

        /* RBAC API with domains.*/
        virtual std::vector<std::string> GetUsersForRoleInDomain(const std::string& name, const std::string& domain) = 0;
        virtual std::vector<std::string> GetRolesForUserInDomain(const std::string& name, const std::string& domain) = 0;
        virtual std::vector<std::vector<std::string>> GetPermissionsForUserInDomain(const std::string& user, const std::string& domain) = 0;
        virtual bool AddRoleForUserInDomain(const std::string& user, const std::string& role, const std::string& domain) = 0;
        virtual bool DeleteRoleForUserInDomain(const std::string& user, const std::string& role, const std::string& domain) = 0;
    };

    // Enforcer is the main interface for authorization enforcement and policy management.
    class Enforcer : public IEnforcer {
    private:

        std::string m_model_path;
        std::shared_ptr<Model> m_model;
        FunctionMap m_func_map;
        std::vector<std::tuple<std::string, Function, Index>> m_user_func_list;
        std::shared_ptr<Effector> m_eft;

        std::shared_ptr<Adapter> m_adapter;
        std::shared_ptr<Watcher> m_watcher;
        LogUtil m_log;

        bool m_enabled;
        bool m_auto_save;
        bool m_auto_build_role_links;
        bool m_auto_notify_watcher;

        // enforce use a custom matcher to decides whether a "subject" can access a "object" 
        // with the operation "action", input parameters are usually: (matcher, sub, obj, act), 
        // use model matcher by default when matcher is "".
        bool m_enforce(const std::string& matcher, Scope scope);

    public:

        std::shared_ptr<RoleManager> rm;

        /**
         * Enforcer is the default constructor.
         */
        Enforcer();
        /**
         * Enforcer initializes an enforcer with a model file and a policy file.
         *
         * @param model_path the path of the model file.
         * @param policy_file the path of the policy file.
         */
        Enforcer(const std::string& model_path, const std::string& policy_file);
        /**
         * Enforcer initializes an enforcer with a database adapter.
         *
         * @param model_path the path of the model file.
         * @param adapter the adapter.
         */
        Enforcer(const std::string& model_path, std::shared_ptr<Adapter> adapter);
        /**
         * Enforcer initializes an enforcer with a model and a database adapter.
         *
         * @param m the model.
         * @param adapter the adapter.
         */
        Enforcer(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter);
        /**
         * Enforcer initializes an enforcer with a model.
         *
         * @param m the model.
         */
        Enforcer(const std::shared_ptr<Model>& m);
        /**
         * Enforcer initializes an enforcer with a model file.
         *
         * @param model_path the path of the model file.
         */
        Enforcer(const std::string& model_path);
        /**
         * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
         *
         * @param model_path the path of the model file.
         * @param policy_file the path of the policy file.
         * @param enable_log whether to enable Casbin's log.
         */
        Enforcer(const std::string& model_path, const std::string& policy_file, bool enable_log);
        // InitWithFile initializes an enforcer with a model file and a policy file.
        void InitWithFile(const std::string& model_path, const std::string& policy_path);
        // InitWithAdapter initializes an enforcer with a database adapter.
        void InitWithAdapter(const std::string& model_path, std::shared_ptr<Adapter> adapter);
        // InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
        void InitWithModelAndAdapter(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter);
        void Initialize();
        // LoadModel reloads the model from the model CONF file.
        // Because the policy is attached to a model, so the policy is invalidated and 
        // needs to be reloaded by calling LoadPolicy().
        void LoadModel();
        // GetModel gets the current model.
        std::shared_ptr<Model> GetModel();
        // SetModel sets the current model.
        void SetModel(const std::shared_ptr<Model>& m);
        // GetAdapter gets the current adapter.
        std::shared_ptr<Adapter> GetAdapter();
        // SetAdapter sets the current adapter.
        void SetAdapter(std::shared_ptr<Adapter> adapter);
        // SetWatcher sets the current watcher.
        void SetWatcher(std::shared_ptr<Watcher> watcher);
        // GetRoleManager gets the current role manager.
        std::shared_ptr<RoleManager> GetRoleManager();
        // SetRoleManager sets the current role manager.
        void SetRoleManager(std::shared_ptr<RoleManager>& rm);
        // SetEffector sets the current effector.
        void SetEffector(std::shared_ptr<Effector> eft);
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
        void EnableLog(bool enable);

        // EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
        void EnableAutoNotifyWatcher(bool enable);
        // EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
        void EnableAutoSave(bool auto_save);
        // EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
        void EnableAutoBuildRoleLinks(bool auto_build_role_links);
        // BuildRoleLinks manually rebuild the role inheritance relations.
        void BuildRoleLinks();
        // BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
        void BuildIncrementalRoleLinks(policy_op op, const std::string& p_type, const std::vector<std::vector<std::string>>& rules);
        // Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(Scope scope);
        // Enforce with a list param, decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(const DataList& params);
        // Enforce with a vector param, decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(const DataVector& params);
        // Enforce with a map param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(const DataMap& params);
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(const std::string& matcher, Scope scope);
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(const std::string& matcher, const DataList& params);
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(const std::string& matcher, const DataVector& params);
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(const std::string& matcher, const DataMap& params);
        // BatchEnforce enforce in batches
        std::vector<bool> BatchEnforce(const std::initializer_list<DataList>& requests);
        // BatchEnforceWithMatcher enforce with matcher in batches
        std::vector<bool> BatchEnforceWithMatcher(const std::string& matcher, const std::initializer_list<DataList>& requests);

        /*Management API member functions.*/
        std::vector<std::string> GetAllSubjects();
        std::vector<std::string> GetAllNamedSubjects(const std::string& p_type);
        std::vector<std::string> GetAllObjects();
        std::vector<std::string> GetAllNamedObjects(const std::string& p_type);
        std::vector<std::string> GetAllActions();
        std::vector<std::string> GetAllNamedActions(const std::string& p_type);
        std::vector<std::string> GetAllRoles();
        std::vector<std::string> GetAllNamedRoles(const std::string& p_type);
        std::vector<std::vector<std::string>> GetPolicy();
        std::vector<std::vector<std::string>> GetFilteredPolicy(int field_index, const std::vector<std::string>& field_values);
        std::vector<std::vector<std::string>> GetNamedPolicy(const std::string& p_type);
        std::vector<std::vector<std::string>> GetFilteredNamedPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values);
        std::vector<std::vector<std::string>> GetGroupingPolicy();
        std::vector<std::vector<std::string>> GetFilteredGroupingPolicy(int field_index, const std::vector<std::string>& field_values);
        std::vector<std::vector<std::string>> GetNamedGroupingPolicy(const std::string& p_type);
        std::vector<std::vector<std::string>> GetFilteredNamedGroupingPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values);
        bool HasPolicy(const std::vector<std::string>& params);
        bool HasNamedPolicy(const std::string& p_type, const std::vector<std::string>& params);
        bool AddPolicy(const std::vector<std::string>& params);
        bool AddPolicies(const std::vector<std::vector<std::string>>& rules);
        bool AddNamedPolicy(const std::string& p_type, const std::vector<std::string>& params);
        bool AddNamedPolicies(const std::string& p_type, const std::vector<std::vector<std::string>>& rules);
        bool RemovePolicy(const std::vector<std::string>& params);
        bool RemovePolicies(const std::vector<std::vector<std::string>>& rules);
        bool RemoveFilteredPolicy(int field_index, const std::vector<std::string>& field_values);
        bool RemoveNamedPolicy(const std::string& p_type, const std::vector<std::string>& params);
        bool RemoveNamedPolicies(const std::string& p_type, const std::vector<std::vector<std::string>>& rules);
        bool RemoveFilteredNamedPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values);
        bool HasGroupingPolicy(const std::vector<std::string>& params);
        bool HasNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params);
        bool AddGroupingPolicy(const std::vector<std::string>& params);
        bool AddGroupingPolicies(const std::vector<std::vector<std::string>>& rules);
        bool AddNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params);
        bool AddNamedGroupingPolicies(const std::string& p_type, const std::vector<std::vector<std::string>>& rules);
        bool RemoveGroupingPolicy(const std::vector<std::string>& params);
        bool RemoveGroupingPolicies(const std::vector<std::vector<std::string>>& rules);
        bool RemoveFilteredGroupingPolicy(int field_index, const std::vector<std::string>& field_values);
        bool RemoveNamedGroupingPolicy(const std::string& p_type, const std::vector<std::string>& params);
        bool RemoveNamedGroupingPolicies(const std::string& p_type, const std::vector<std::vector<std::string>>& rules);
        bool RemoveFilteredNamedGroupingPolicy(const std::string& p_type, int field_index, const std::vector<std::string>& field_values);
        void AddFunction(const std::string& name, Function function, Index nargs);
        bool UpdateGroupingPolicy(const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule);
        bool UpdateNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule);
        bool UpdatePolicy(const std::vector<std::string>& oldPolicy, const std::vector<std::string>& newPolicy);
        bool UpdateNamedPolicy(const std::string& ptype, const std::vector<std::string>& p1, const std::vector<std::string>& p2);
        bool UpdatePolicies(const std::vector<std::vector<std::string>>& oldPolices, const std::vector<std::vector<std::string>>& newPolicies);
        bool UpdateNamedPolicies(const std::string& ptype, const std::vector<std::vector<std::string>>& p1, const std::vector<std::vector<std::string>>& p2);

        /*RBAC API member functions.*/
        std::vector<std::string> GetRolesForUser(const std::string& name, const std::vector<std::string>& domain = {});
        std::vector<std::string> GetUsersForRole(const std::string& name, const std::vector<std::string>& domain = {});
        bool HasRoleForUser(const std::string& name, const std::string& role);
        bool AddRoleForUser(const std::string& user, const std::string& role);
        bool AddRolesForUser(const std::string& user, const std::vector<std::string>& roles);
        bool AddPermissionForUser(const std::string& user, const std::vector<std::string>& permission);
        bool DeletePermissionForUser(const std::string& user, const std::vector<std::string>& permission);
        bool DeletePermissionsForUser(const std::string& user);
        std::vector<std::vector<std::string>> GetPermissionsForUser(const std::string& user);
        bool HasPermissionForUser(const std::string& user, const std::vector<std::string>& permission);
        std::vector<std::string> GetImplicitRolesForUser(const std::string& name, const std::vector<std::string>& domain = {});
        std::vector<std::vector<std::string>> GetImplicitPermissionsForUser(const std::string& user, const std::vector<std::string>& domain = {});
        std::vector<std::string> GetImplicitUsersForPermission(const std::vector<std::string>& permission);
        bool DeleteRoleForUser(const std::string& user, const std::string& role);
        bool DeleteRolesForUser(const std::string& user);
        bool DeleteUser(const std::string& user);
        bool DeleteRole(const std::string& role);
        bool DeletePermission(const std::vector<std::string>& permission);

        /* Internal API member functions */
        bool addPolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& rule);
        bool addPolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules);
        bool removePolicy(const std::string& sec , const std::string& p_type , const std::vector<std::string>& rule);
        bool removePolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& rules);
        bool removeFilteredPolicy(const std::string& sec , const std::string& p_type , int field_index , const std::vector<std::string>& field_values);
        bool updatePolicy(const std::string& sec, const std::string& p_type, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule);
        bool updatePolicies(const std::string& sec, const std::string& p_type, const std::vector<std::vector<std::string>>& p1, const std::vector<std::vector<std::string>>& p2);

        /* RBAC API with domains.*/
        std::vector<std::string> GetUsersForRoleInDomain(const std::string& name, const std::string& domain = {});
        std::vector<std::string> GetRolesForUserInDomain(const std::string& name, const std::string& domain = {});
        std::vector<std::vector<std::string>> GetPermissionsForUserInDomain(const std::string& user, const std::string& domain = {});
        bool AddRoleForUserInDomain(const std::string& user, const std::string& role, const std::string& domain = {});
        bool DeleteRoleForUserInDomain(const std::string& user, const std::string& role, const std::string& domain = {});
    };

    class CachedEnforcer : public Enforcer {
    public:
        std::unordered_map<std::string, bool> m;
        bool enableCache;
        std::mutex locker;
    
        CachedEnforcer(const CachedEnforcer& ce);
        CachedEnforcer(CachedEnforcer&& ce);
    
        void EnableCache(const bool& enableCache);
        std::pair<bool, bool> getCachedResult(const std::string& key);
        void setCachedResult(const std::string& key, const bool& res);
        void InvalidateCache();
    
    public:
         /**
             * Enforcer is the default constructor.
         */
        CachedEnforcer();
        /**
             * Enforcer initializes an enforcer with a model file and a policy file.
             *
             * @param model_path the path of the model file.
             * @param policy_file the path of the policy file.
             */
        CachedEnforcer(const std::string& model_path, const std::string& policy_file);
        /**
             * Enforcer initializes an enforcer with a database adapter.
             *
             * @param model_path the path of the model file.
             * @param adapter the adapter.
             */
        CachedEnforcer(const std::string& model_path, std::shared_ptr<Adapter> adapter);
        /**
             * Enforcer initializes an enforcer with a model and a database adapter.
             *
             * @param m the model.
             * @param adapter the adapter.
             */
        CachedEnforcer(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter);
        /**
             * Enforcer initializes an enforcer with a model.
             *
             * @param m the model.
             */
        CachedEnforcer(const std::shared_ptr<Model>& m);
        /**
             * Enforcer initializes an enforcer with a model file.
             *
             * @param model_path the path of the model file.
             */
        CachedEnforcer(const std::string& model_path);
        /**
             * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
             *
             * @param model_path the path of the model file.
             * @param policy_file the path of the policy file.
             * @param enable_log whether to enable Casbin's log.
             */
        CachedEnforcer(const std::string& model_path, const std::string& policy_file, bool enable_log);
    
        bool Enforce(Scope scope);
    
        // Enforce with a vector param,decides whether a "subject" can access a
        // "object" with the operation "action", input parameters are usually: (sub,
        // obj, act).
        bool Enforce(const DataVector& params);
    
        // Enforce with a vector param,decides whether a "subject" can access a
        // "object" with the operation "action", input parameters are usually: (sub,
        // obj, act).
        bool Enforce(const DataList& params);
    
        // Enforce with a map param,decides whether a "subject" can access a "object"
        // with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(const DataMap& params);
    
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
        // access a "object" with the operation "action", input parameters are
        // usually: (matcher, sub, obj, act), use model matcher by default when
        // matcher is "".
        bool EnforceWithMatcher(const std::string& matcher, Scope scope);
    
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
        // access a "object" with the operation "action", input parameters are
        // usually: (matcher, sub, obj, act), use model matcher by default when
        // matcher is "".
        bool EnforceWithMatcher(const std::string& matcher, const DataVector& params);
    
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
        // access a "object" with the operation "action", input parameters are
        // usually: (matcher, sub, obj, act), use model matcher by default when
        // matcher is "".
        bool EnforceWithMatcher(const std::string& matcher, const DataList& params);
    
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
        // access a "object" with the operation "action", input parameters are
        // usually: (matcher, sub, obj, act), use model matcher by default when
        // matcher is "".
        bool EnforceWithMatcher(const std::string& matcher, const DataMap& params);
    };

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
        SyncedEnforcer(const std::string& model_path, const std::string& policy_file);

        /**
            * Enforcer initializes an enforcer with a database adapter.
            *
            * @param model_path the path of the model file.
            * @param adapter the adapter.
        */
        SyncedEnforcer(const std::string& model_path, std::shared_ptr<Adapter> adapter);

        /**
            * Enforcer initializes an enforcer with a model and a database adapter.
            *
            * @param m the model.
            * @param adapter the adapter.
        */
        SyncedEnforcer(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter);

        /**
            * Enforcer initializes an enforcer with a model.
            *
            * @param m the model.
        */
        SyncedEnforcer(const std::shared_ptr<Model>& m);

        /**
            * Enforcer initializes an enforcer with a model file.
            *
            * @param model_path the path of the model file.
        */
        SyncedEnforcer(const std::string& model_path);

        /**
            * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
            *
            * @param model_path the path of the model file.
            * @param policy_file the path of the policy file.
            * @param enable_log whether to enable Casbin's log.
        */
        SyncedEnforcer(const std::string& model_path, const std::string& policy_file, bool enable_log);

        // StartAutoLoadPolicy starts a thread that will go through every specified duration call LoadPolicy
        void StartAutoLoadPolicy(std::chrono::duration<int64_t, std::nano> t);

        // IsAutoLoadingRunning check if SyncedEnforcer is auto loading policies
        bool IsAutoLoadingRunning();

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
        bool Enforce(const DataVector& params);

        // Enforce with a vector param,decides whether a "subject" can access a
        // "object" with the operation "action", input parameters are usually: (sub,
        // obj, act).
        bool Enforce(const DataList& params);

        // Enforce with a map param,decides whether a "subject" can access a "object"
        // with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(const DataMap& params);

        // BatchEnforce enforce in batches
        std::vector<bool> BatchEnforce(const std::initializer_list<DataList>& requests);

        // BatchEnforceWithMatcher enforce with matcher in batches
        std::vector<bool> BatchEnforceWithMatcher(const std::string& matcher, const std::initializer_list<DataList>& requests);

        // GetAllSubjects gets the list of subjects that show up in the current policy.
        std::vector<std::string> GetAllSubjects();

        // GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
        std::vector<std::string> GetAllNamedSubjects(const std::string& ptype);

        // GetAllObjects gets the list of objects that show up in the current policy.
        std::vector<std::string> GetAllObjects();

        // GetAllNamedObjects gets the list of objects that show up in the current named policy.
        std::vector<std::string> GetAllNamedObjects(const std::string& ptype);

        // GetAllNamedActions gets the list of actions that show up in the current named policy.
        std::vector<std::string> GetAllNamedActions(const std::string& ptype);

        // GetAllRoles gets the list of roles that show up in the current policy.
        std::vector<std::string> GetAllRoles();

        // GetAllNamedRoles gets the list of roles that show up in the current named policy.
        std::vector<std::string> GetAllNamedRoles(const std::string& ptype);

        // GetPolicy gets all the authorization rules in the policy.
        std::vector<std::vector<std::string>> GetPolicy();

        // GetNamedPolicy gets all the authorization rules in the named policy.
        std::vector<std::vector<std::string>> GetNamedPolicy(const std::string& ptype);

        // GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
        std::vector<std::vector<std::string>> GetFilteredNamedPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues);

        // GetGroupingPolicy gets all the role inheritance rules in the policy.
        std::vector<std::vector<std::string>> GetGroupingPolicy();

        // GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
        std::vector<std::vector<std::string>> GetFilteredGroupingPolicy(int fieldIndex, const std::vector<std::string>& fieldValues);

        // GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
        std::vector<std::vector<std::string>> GetNamedGroupingPolicy(const std::string& ptype);

        // GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
        std::vector<std::vector<std::string>> GetFilteredNamedGroupingPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues);

        // HasPolicy determines whether an authorization rule exists.
        bool HasPolicy(const std::vector<std::string>& params);

        // HasNamedPolicy determines whether a named authorization rule exists.
        bool HasNamedPolicy(const std::string& ptype, const std::vector<std::string>& params);

        // AddPolicy adds an authorization rule to the current policy.
        // If the rule already exists, the function returns false and the rule will not be added.
        // Otherwise the function returns true by adding the new rule.
        bool AddPolicy(const std::vector<std::string>& params);

        // AddPolicies adds authorization rules to the current policy.
        // If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
        // Otherwise the function returns true for the corresponding rule by adding the new rule.
        bool AddPolicies(const std::vector<std::vector<std::string>>& rules);

        // AddNamedPolicy adds an authorization rule to the current named policy.
        // If the rule already exists, the function returns false and the rule will not be added.
        // Otherwise the function returns true by adding the new rule.
        bool AddNamedPolicy(const std::string& ptype, const std::vector<std::string>& params);

        // AddNamedPolicies adds authorization rules to the current named policy.
        // If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
        // Otherwise the function returns true for the corresponding by adding the new rule.
        bool AddNamedPolicies(const std::string& ptype, const std::vector<std::vector<std::string>>& rules);

        // RemovePolicy removes an authorization rule from the current policy.
        bool RemovePolicy(const std::vector<std::string>& params);

        // UpdatePolicy updates an authorization rule from the current policy.
        bool UpdatePolicy(const std::vector<std::string>& oldPolicy, const std::vector<std::string>& newPolicy);

        bool UpdateNamedPolicy(const std::string& ptype, const std::vector<std::string>& p1, const std::vector<std::string>& p2);

        // UpdatePolicies updates authorization rules from the current policies.
        bool UpdatePolicies(const std::vector<std::vector<std::string>>& oldPolices, const std::vector<std::vector<std::string>>& newPolicies);

        bool UpdateNamedPolicies(const std::string& ptype, const std::vector<std::vector<std::string>>& p1, const std::vector<std::vector<std::string>>& p2);

        // RemovePolicies removes authorization rules from the current policy.
        bool RemovePolicies(const std::vector<std::vector<std::string>>& rules);

        // RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
        bool RemoveFilteredPolicy(int fieldIndex, const std::vector<std::string>& fieldValues);

        // RemoveNamedPolicy removes an authorization rule from the current named policy.
        bool RemoveNamedPolicy(const std::string& ptype, const std::vector<std::string>& params);

        // RemoveNamedPolicies removes authorization rules from the current named policy.
        bool RemoveNamedPolicies(const std::string& ptype, const std::vector<std::vector<std::string>>& rules);

        // RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
        bool RemoveFilteredNamedPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues);

        // HasGroupingPolicy determines whether a role inheritance rule exists.
        bool HasGroupingPolicy(const std::vector<std::string>& params);

        // HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
        bool HasNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& params);

        // AddGroupingPolicy adds a role inheritance rule to the current policy.
        // If the rule already exists, the function returns false and the rule will not be added.
        // Otherwise the function returns true by adding the new rule.
        bool AddGroupingPolicy(const std::vector<std::string>& params);

        // AddGroupingPolicies adds role inheritance rulea to the current policy.
        // If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
        // Otherwise the function returns true for the corresponding policy rule by adding the new rule.
        bool AddGroupingPolicies(const std::vector<std::vector<std::string>>& rules);

        // AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
        // If the rule already exists, the function returns false and the rule will not be added.
        // Otherwise the function returns true by adding the new rule.
        bool AddNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& params);

        // AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
        // If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
        // Otherwise the function returns true for the corresponding policy rule by adding the new rule.
        bool AddNamedGroupingPolicies(const std::string& ptype, const std::vector<std::vector<std::string>>& rules);

        // RemoveGroupingPolicy removes a role inheritance rule from the current policy.
        bool RemoveGroupingPolicy(const std::vector<std::string>& params);

        // RemoveGroupingPolicies removes role inheritance rules from the current policy.
        bool RemoveGroupingPolicies(const std::vector<std::vector<std::string>>& rules);

        // RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
        bool RemoveFilteredGroupingPolicy(int fieldIndex, const std::vector<std::string>& fieldValues);

        // RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
        bool RemoveNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& params);

        // RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
        bool RemoveNamedGroupingPolicies(const std::string& ptype, const std::vector<std::vector<std::string>>& rules);

        bool UpdateGroupingPolicy(const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule);

        bool UpdateNamedGroupingPolicy(const std::string& ptype, const std::vector<std::string>& oldRule, const std::vector<std::string>& newRule);

        // RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
        bool RemoveFilteredNamedGroupingPolicy(const std::string& ptype, int fieldIndex, const std::vector<std::string>& fieldValues);

        // AddFunction adds a customized function.
        void AddFunction(const std::string& name, Function function, Index nargs);
    };

} // namespace casbin

#endif //CASBIN_CPP_ENFORCER_H
