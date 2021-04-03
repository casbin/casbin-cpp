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

#ifndef CASBIN_CPP_ENFORCER_INTERFACE
#define CASBIN_CPP_ENFORCER_INTERFACE

#include "./model/model.h"
#include "./persist/adapter.h"
#include "./persist/default_watcher.h"
#include "./effect/effector.h"
#include "./model/scope_config.h"

namespace casbin {

// IEnforcer is the API interface of Enforcer
class IEnforcer {
    public:

        /* Enforcer API */
        virtual void InitWithFile(std::string model_path, std::string policy_path) = 0;
        virtual void InitWithAdapter(std::string model_path, std::shared_ptr<Adapter> adapter) = 0;
        virtual void InitWithModelAndAdapter(std::shared_ptr<Model> m, std::shared_ptr<Adapter> adapter) = 0;
        virtual void Initialize() = 0;
        virtual void LoadModel() = 0;
        virtual std::shared_ptr<Model> GetModel() = 0;
        virtual void SetModel(std::shared_ptr<Model> m) = 0;
        virtual std::shared_ptr<Adapter> GetAdapter() = 0;
        virtual void SetAdapter(std::shared_ptr<Adapter> adapter) = 0;
        virtual void SetWatcher(std::shared_ptr<Watcher> watcher) = 0;
        virtual std::shared_ptr<RoleManager> GetRoleManager() = 0;
        virtual void SetRoleManager(std::shared_ptr<RoleManager> rm) = 0;
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
        virtual bool enforce(std::string matcher, Scope scope) = 0;
        virtual bool Enforce(Scope scope) = 0;
        virtual bool EnforceWithMatcher(std::string matcher, Scope scope) = 0;

        /* RBAC API */
        virtual std::vector<std::string> GetRolesForUser(std::string name, std::vector<std::string> domain = {}) = 0;
        virtual std::vector<std::string> GetUsersForRole(std::string name, std::vector<std::string> domain = {}) = 0;
        virtual bool HasRoleForUser(std::string name, std::string role) = 0;
        virtual bool AddRoleForUser(std::string user, std::string role) = 0;
        virtual bool AddRolesForUser(std::string user, std::vector<std::string> roles) = 0;
        virtual bool AddPermissionForUser(std::string user, std::vector<std::string> permission) = 0;
        virtual bool DeletePermissionForUser(std::string user, std::vector<std::string> permission) = 0;
        virtual bool DeletePermissionsForUser(std::string user) = 0;
        virtual std::vector<std::vector<std::string>> GetPermissionsForUser(std::string user) = 0;
        virtual bool HasPermissionForUser(std::string user, std::vector<std::string> permission) = 0;
        virtual std::vector<std::string> GetImplicitRolesForUser(std::string name, std::vector<std::string> domain = {}) = 0;
        virtual std::vector<std::vector<std::string>> GetImplicitPermissionsForUser(std::string user, std::vector<std::string> domain = {}) = 0;
        virtual std::vector<std::string> GetImplicitUsersForPermission(std::vector<std::string> permission) = 0;
        virtual bool DeleteRoleForUser(std::string user, std::string role) = 0;
        virtual bool DeleteRolesForUser(std::string user) = 0;
        virtual bool DeleteUser(std::string user) = 0;
        virtual bool DeleteRole(std::string role) = 0;
        virtual bool DeletePermission(std::vector<std::string> permission) = 0;

        /* Management API */
        virtual std::vector<std::string> GetAllSubjects() = 0;
        virtual std::vector<std::string> GetAllNamedSubjects(std::string p_type) = 0;
        virtual std::vector<std::string> GetAllObjects() = 0;
        virtual std::vector<std::string> GetAllNamedObjects(std::string p_type) = 0;
        virtual std::vector<std::string> GetAllActions() = 0;
        virtual std::vector<std::string> GetAllNamedActions(std::string p_type) = 0;
        virtual std::vector<std::string> GetAllRoles() = 0;
        virtual std::vector<std::string> GetAllNamedRoles(std::string p_type) = 0;
        virtual std::vector<std::vector<std::string>> GetPolicy() = 0;
        virtual std::vector<std::vector<std::string>> GetFilteredPolicy(int field_index, std::vector<std::string> field_values) = 0;
        virtual std::vector<std::vector<std::string>> GetNamedPolicy(std::string p_type) = 0;
        virtual std::vector<std::vector<std::string>> GetFilteredNamedPolicy(std::string p_type, int field_index, std::vector<std::string> field_values) = 0;
        virtual std::vector<std::vector<std::string>> GetGroupingPolicy() = 0;
        virtual std::vector<std::vector<std::string>> GetFilteredGroupingPolicy(int field_index, std::vector<std::string> field_values) = 0;
        virtual std::vector<std::vector<std::string>> GetNamedGroupingPolicy(std::string p_type) = 0;
        virtual std::vector<std::vector<std::string>> GetFilteredNamedGroupingPolicy(std::string p_type, int field_index, std::vector<std::string> field_values) = 0;
        virtual bool HasPolicy(std::vector<std::string> params) = 0;
        virtual bool HasNamedPolicy(std::string p_type, std::vector<std::string> params) = 0;
        virtual bool AddPolicy(std::vector<std::string> params) = 0;
        virtual bool  AddPolicies(std::vector<std::vector<std::string>> rules) = 0;
        virtual bool AddNamedPolicy(std::string p_type, std::vector<std::string> params) = 0;
        virtual bool AddNamedPolicies(std::string p_type, std::vector<std::vector<std::string>> rules) = 0;
        virtual bool RemovePolicy(std::vector<std::string> params) = 0;
        virtual bool RemovePolicies(std::vector<std::vector<std::string>> rules) = 0;
        virtual bool RemoveFilteredPolicy(int field_index, std::vector<std::string> field_values) = 0;
        virtual bool RemoveNamedPolicy(std::string p_type, std::vector<std::string> params) = 0;
        virtual bool RemoveNamedPolicies(std::string p_type, std::vector<std::vector<std::string>> rules) = 0;
        virtual bool RemoveFilteredNamedPolicy(std::string p_type, int field_index, std::vector<std::string> field_values) = 0;
        virtual bool HasGroupingPolicy(std::vector<std::string> params) = 0;
        virtual bool HasNamedGroupingPolicy(std::string p_type, std::vector<std::string> params) = 0;
        virtual bool AddGroupingPolicy(std::vector<std::string> params) = 0;
        virtual bool AddGroupingPolicies(std::vector<std::vector<std::string>> rules) = 0;
        virtual bool AddNamedGroupingPolicy(std::string p_type, std::vector<std::string> params) = 0;
        virtual bool AddNamedGroupingPolicies(std::string p_type, std::vector<std::vector<std::string>> rules) = 0;
        virtual bool RemoveGroupingPolicy(std::vector<std::string> params) = 0;
        virtual bool RemoveGroupingPolicies(std::vector<std::vector<std::string>> rules) = 0;
        virtual bool RemoveFilteredGroupingPolicy(int field_index, std::vector<std::string> field_values) = 0;
        virtual bool RemoveNamedGroupingPolicy(std::string p_type, std::vector<std::string> params) = 0;
        virtual bool RemoveNamedGroupingPolicies(std::string p_type, std::vector<std::vector<std::string>> rules) = 0;
        virtual bool RemoveFilteredNamedGroupingPolicy(std::string p_type, int field_index, std::vector<std::string> field_values) = 0;
        virtual void AddFunction(std::string name, Function function, Index nargs) = 0;

        /* Internal API member functions */
        virtual bool addPolicy(std::string sec, std::string p_type, std::vector<std::string> rule) = 0;
        virtual bool addPolicies(std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules) = 0;
        virtual bool removePolicy(std::string sec , std::string p_type , std::vector<std::string> rule) = 0;
        virtual bool removePolicies(std::string sec, std::string p_type, std::vector<std::vector<std::string>> rules) = 0;
        virtual bool removeFilteredPolicy(std::string sec , std::string p_type , int field_index , std::vector<std::string> field_values) = 0;

        /* RBAC API with domains.*/
        virtual std::vector<std::string> GetUsersForRoleInDomain(std::string name, std::string domain) = 0;
        virtual std::vector<std::string> GetRolesForUserInDomain(std::string name, std::string domain) = 0;
        virtual std::vector<std::vector<std::string>> GetPermissionsForUserInDomain(std::string user, std::string domain) = 0;
        virtual bool AddRoleForUserInDomain(std::string user, std::string role, std::string domain) = 0;
        virtual bool DeleteRoleForUserInDomain(std::string user, std::string role, std::string domain) = 0;
};

} // namespace casbin

#endif