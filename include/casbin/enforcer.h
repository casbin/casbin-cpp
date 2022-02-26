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

#include <tuple>
#include <vector>
#include "casbin/rbac/role_manager.h"
#include "casbin/model/function.h"
#include "casbin/enforcer_interface.h"
#include "casbin/persist/filtered_adapter.h"
#include "casbin/log/log_util.h"
#include "casbin/model/evaluator.h"

namespace casbin {

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
        std::shared_ptr<IEvaluator> m_evalator;
        LogUtil m_log;

        bool m_enabled;
        bool m_auto_save;
        bool m_auto_build_role_links;
        bool m_auto_notify_watcher;

        // enforce use a custom matcher to decides whether a "subject" can access a "object" 
        // with the operation "action", input parameters are usually: (matcher, sub, obj, act), 
        // use model matcher by default when matcher is "".
        bool m_enforce(const std::string& matcher, std::shared_ptr<IEvaluator> evalator);
        // clean scope to prepare next enforce
        void clean_scope(std::string section_name);

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
        // Destructor of Enforcer.
        ~Enforcer();
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
        bool Enforce(std::shared_ptr<IEvaluator> evalator);
        // Enforce with a list param, decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(const DataList& params);
        // Enforce with a vector param, decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(const DataVector& params);
        // Enforce with a map param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(const DataMap& params);
        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator);
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
        bool AddNamedMatchingFunc(const std::string& ptype, const std::string& name, casbin::MatchingFunc func);

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

} // namespace casbin

#endif