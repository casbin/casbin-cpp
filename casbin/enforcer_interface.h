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

// IEnforcer is the API interface of Enforcer
class IEnforcer {
    public:

        /* Enforcer API */
        virtual void InitWithFile(string modelPath, string policyPath) = 0;
        virtual void InitWithAdapter(string modelPath, shared_ptr<Adapter> adapter) = 0;
        virtual void InitWithModelAndAdapter(shared_ptr<Model> m, shared_ptr<Adapter> adapter) = 0;
        virtual void Initialize() = 0;
        virtual void LoadModel() = 0;
        virtual shared_ptr<Model> GetModel() = 0;
        virtual void SetModel(shared_ptr<Model> m) = 0;
        virtual shared_ptr<Adapter> GetAdapter() = 0;
        virtual void SetAdapter(shared_ptr<Adapter> adapter) = 0;
        virtual void SetWatcher(shared_ptr<Watcher> watcher) = 0;
        virtual shared_ptr<RoleManager> GetRoleManager() = 0;
        virtual void SetRoleManager(shared_ptr<RoleManager> rm) = 0;
        virtual void SetEffector(shared_ptr<Effector> eft) = 0;
        virtual void ClearPolicy() = 0;
        virtual void LoadPolicy() = 0;

        template<typename Filter>
        void LoadFilteredPolicy(Filter filter);

        virtual bool IsFiltered() = 0;
        virtual void SavePolicy() = 0;
        virtual void EnableEnforce(bool enable) = 0;
        // virtual void EnableLog(bool enable) = 0;
        virtual void EnableAutoNotifyWatcher(bool enable) = 0;
        virtual void EnableAutoSave(bool autoSave) = 0;
        virtual void EnableAutoBuildRoleLinks(bool autoBuildRoleLinks) = 0;
        virtual void BuildRoleLinks() = 0;
        virtual bool enforce(string matcherc, Scope scope) = 0;
        virtual bool Enforce(Scope scope) = 0;
        virtual bool EnforceWithMatcher(string matcher, Scope scope) = 0;

        /* RBAC API */
        virtual vector<string> GetRolesForUser(string name, vector<string> domain = {}) = 0;
        virtual vector<string> GetUsersForRole(string name, vector<string> domain = {}) = 0;
        virtual bool HasRoleForUser(string name, string role) = 0;
        virtual bool AddRoleForUser(string user, string role) = 0;
        virtual bool AddRolesForUser(string user, vector<string> roles) = 0;
        virtual bool AddPermissionForUser(string user, vector<string> permission) = 0;
        virtual bool DeletePermissionForUser(string user, vector<string> permission) = 0;
        virtual bool DeletePermissionsForUser(string user) = 0;
        virtual vector<vector<string>> GetPermissionsForUser(string user) = 0;
        virtual bool HasPermissionForUser(string user, vector<string> permission) = 0;
        virtual vector<string> GetImplicitRolesForUser(string name, vector<string> domain = {}) = 0;
        virtual vector<vector<string>> GetImplicitPermissionsForUser(string user, vector<string> domain = {}) = 0;
        virtual vector<string> GetImplicitUsersForPermission(vector<string> permission) = 0;
        virtual bool DeleteRoleForUser(string user, string role) = 0;
        virtual bool DeleteRolesForUser(string user) = 0;
        virtual bool DeleteUser(string user) = 0;
        virtual bool DeleteRole(string role) = 0;
        virtual bool DeletePermission(vector<string> permission) = 0;

        /* Management API */
        virtual vector<string> GetAllSubjects() = 0;
        virtual vector<string> GetAllNamedSubjects(string ptype) = 0;
        virtual vector<string> GetAllObjects() = 0;
        virtual vector<string> GetAllNamedObjects(string ptype) = 0;
        virtual vector<string> GetAllActions() = 0;
        virtual vector<string> GetAllNamedActions(string ptype) = 0;
        virtual vector<string> GetAllRoles() = 0;
        virtual vector<string> GetAllNamedRoles(string ptype) = 0;
        virtual vector<vector<string>> GetPolicy() = 0;
        virtual vector<vector<string>> GetFilteredPolicy(int fieldIndex, vector<string> fieldValues) = 0;
        virtual vector<vector<string>> GetNamedPolicy(string ptype) = 0;
        virtual vector<vector<string>> GetFilteredNamedPolicy(string ptype, int fieldIndex, vector<string> fieldValues) = 0;
        virtual vector<vector<string>> GetGroupingPolicy() = 0;
        virtual vector<vector<string>> GetFilteredGroupingPolicy(int fieldIndex, vector<string> fieldValues) = 0;
        virtual vector<vector<string>> GetNamedGroupingPolicy(string ptype) = 0;
        virtual vector<vector<string>> GetFilteredNamedGroupingPolicy(string ptype, int fieldIndex, vector<string> fieldValues) = 0;
        virtual bool HasPolicy(vector<string> params) = 0;
        virtual bool HasNamedPolicy(string ptype, vector<string> params) = 0;
        virtual bool AddPolicy(vector<string> params) = 0;
        virtual bool  AddPolicies(vector<vector<string>> rules) = 0;
        virtual bool AddNamedPolicy(string ptype, vector<string> params) = 0;
        virtual bool AddNamedPolicies(string p_type, vector<vector<string>> rules) = 0;
        virtual bool RemovePolicy(vector<string> params) = 0;
        virtual bool RemovePolicies(vector<vector<string>> rules) = 0;
        virtual bool RemoveFilteredPolicy(int field_index, vector<string> field_values) = 0;
        virtual bool RemoveNamedPolicy(string ptype, vector<string> params) = 0;
        virtual bool RemoveNamedPolicies(string p_type, vector<vector<string>> rules) = 0;
        virtual bool RemoveFilteredNamedPolicy(string ptype, int field_index, vector<string> field_values) = 0;
        virtual bool HasGroupingPolicy(vector<string> params) = 0;
        virtual bool HasNamedGroupingPolicy(string ptype, vector<string> params) = 0;
        virtual bool AddGroupingPolicy(vector<string> params) = 0;
        virtual bool AddGroupingPolicies(vector<vector<string>> rules) = 0;
        virtual bool AddNamedGroupingPolicy(string ptype, vector<string> params) = 0;
        virtual bool AddNamedGroupingPolicies(string p_type, vector<vector<string>> rules) = 0;
        virtual bool RemoveGroupingPolicy(vector<string> params) = 0;
        virtual bool RemoveGroupingPolicies(vector<vector<string>> rules) = 0;
        virtual bool RemoveFilteredGroupingPolicy(int field_index, vector<string> field_values) = 0;
        virtual bool RemoveNamedGroupingPolicy(string ptype, vector<string> params) = 0;
        virtual bool RemoveNamedGroupingPolicies(string p_type, vector<vector<string>> rules) = 0;
        virtual bool RemoveFilteredNamedGroupingPolicy(string ptype, int fieldIndex, vector<string> fieldValues) = 0;
        virtual void AddFunction(string name, Function function, Index nargs) = 0;

        /* Internal API member functions */
        virtual bool addPolicy(string sec, string ptype, vector<string> rule) = 0;
        virtual bool addPolicies(string sec, string p_type, vector<vector<string>> rules) = 0;
        virtual bool removePolicy(string sec , string ptype , vector<string> rule) = 0;
        virtual bool removePolicies(string sec, string p_type, vector<vector<string>> rules) = 0;
        virtual bool removeFilteredPolicy(string sec , string ptype , int fieldIndex , vector<string> fieldValues) = 0;

        /* RBAC API with domains.*/
        virtual vector<string> GetUsersForRoleInDomain(string name, string domain) = 0;
        virtual vector<string> GetRolesForUserInDomain(string name, string domain) = 0;
        virtual vector<vector<string>> GetPermissionsForUserInDomain(string user, string domain) = 0;
        virtual bool AddRoleForUserInDomain(string user, string role, string domain) = 0;
        virtual bool DeleteRoleForUserInDomain(string user, string role, string domain) = 0;
};

#endif