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

#include "./exception/CasbinEnforcerException.h"
#include "./model/function.h"
#include "./rbac/default_role_manager.h"
#include "./effect/default_effector.h"
#include "./enforcer_interface.h"
#include "./persist/file-adapter/file_adapter.h"
#include "./persist/file-adapter/filtered_adapter.h"

// Enforcer is the main interface for authorization enforcement and policy management.
class Enforcer : public IEnforcer{
    private:

        string model_path;
        Model* model;
        FunctionMap func_map;
        Effector* eft;

        Adapter* adapter;
        Watcher* watcher;
        RoleManager* rm;

        bool enabled;
        bool auto_save;
        bool auto_build_role_links;
        bool auto_notify_watcher;

        // enforce use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool enforce(string matcher, Scope scope) {
            // TODO
            // defer func() {
            // 	if err := recover(); err != nil {
            // 		fmt.Errorf("panic: %v", err)
            // 	}
            // }()

            this->func_map.scope = scope;

            if(this->enabled)
                return true;

            // for(unordered_map <string, Function> :: iterator it = this->fm.fmap.begin() ; it != this->fm.fmap.end() ; it++)
            // 	this->fm.AddFunction(it->first, it->second);

            string expString;
            if(matcher == "")
                expString = this->model->m["m"].assertion_map["m"]->value;
            else
                expString = matcher;

            unordered_map <string, RoleManager*> rm_map;
            bool ok = this->model->m.find("g") != this->model->m.end();
            if(ok) {
                for(unordered_map <string, Assertion*> :: iterator it = this->model->m["g"].assertion_map.begin() ; it != this->model->m["g"].assertion_map.end() ; it++){
                    RoleManager* rm = it->second->rm;
                    int index = expString.find((it->first)+"(");
                    if(index != string::npos)
                        expString.insert(index+(it->first+"(").length()-1, (it->first)+"_rm");
                    PushPointer(this->func_map.scope, (void *)rm, (it->first)+"_rm");
                    this->func_map.AddFunction(it->first, GFunction);
                }
            }

            unordered_map <string, int> pIntTokens;
            for(int i = 0 ; i < this->model->m["p"].assertion_map["p"]->tokens.size() ; i++)
                pIntTokens[this->model->m["p"].assertion_map["p"]->tokens[i]] = i;

            vector <string> pTokens = this->model->m["p"].assertion_map["p"]->tokens;

            vector <Effect> policyEffects;
            vector <float> matcherResults;

            int policyLen = this->model->m["p"].assertion_map["p"]->policy.size();

            if(policyLen != 0) {
                if(this->model->m["r"].assertion_map["r"]->tokens.size() != this->func_map.GetRLen())
                    return false;

                //TODO
                for( int i = 0 ; i < this->model->m["p"].assertion_map["p"]->policy.size() ; i++){
                    // log.LogPrint("Policy Rule: ", pvals)
                    vector<string> pVals = this->model->m["p"].assertion_map["p"]->policy[i];
                    if(this->model->m["p"].assertion_map["p"]->tokens.size() != pVals.size())
                        return false;

                    PushObject(this->func_map.scope, "p");
                    for(int j = 0 ; j < pTokens.size() ; j++){
                        int index = pTokens[j].find("_");
                        string token = pTokens[j].substr(index+1);
                        PushStringPropToObject(this->func_map.scope, "p", pVals[j], token);
                    }

                    this->func_map.Eval(expString);
                    //TODO
                    // log.LogPrint("Result: ", result)

                    if(CheckType(this->func_map.scope) == Type :: Bool){
                        bool result = GetBoolean(this->func_map.scope);
                        if(!result) {
                            policyEffects[i] = Effect :: Indeterminate;
                            continue;
                        }
                    }
                    else if(CheckType(this->func_map.scope) == Type :: Float){
                        bool result = GetFloat(this->func_map.scope);
                        if(result == 0) {
                            policyEffects[i] = Effect :: Indeterminate;
                            continue;
                        } else
                            matcherResults[i] = result;
                    }
                    else
                        return false;

                    bool ok = pIntTokens.find("p_eft") != pIntTokens.end();
                    if(ok) {
                        int j = pIntTokens["p_eft"];
                        string eft = pVals[j];
                        if(eft == "allow")
                            policyEffects[i] = Effect :: Allow;
                        else if(eft == "deny")
                            policyEffects[i] = Effect :: Deny;
                        else
                            policyEffects[i] = Effect :: Indeterminate;
                    }
                    else
                        policyEffects[i] = Effect :: Allow;

                    if(this->model->m["e"].assertion_map["e"]->value == "priority(p_eft) || deny")
                        break;
                }
            } else {
                this->func_map.Eval(expString);
                bool result = this->func_map.GetBooleanResult();
                //TODO
                // log.LogPrint("Result: ", result)

                if(result)
                    policyEffects[0] = Effect::Allow;
                else
                    policyEffects[0] = Effect::Indeterminate;
            }

            //TODO
            // log.LogPrint("Rule Results: ", policyEffects)

            bool result = this->eft->MergeEffects(this->model->m["e"].assertion_map["e"]->value, policyEffects, matcherResults);
            
            return result;
        }

    public:

        /**
         * Enforcer is the default constructor.
         */
        static Enforcer* NewEnforcer() {
            Enforcer* e = new Enforcer;
            return e;
        }

        /**
         * Enforcer initializes an enforcer with a model file and a policy file.
         *
         * @param model_path the path of the model file.
         * @param policyFile the path of the policy file.
         */
        static Enforcer* NewEnforcer(string model_path, string policyFile) {
            return NewEnforcer(model_path, FileAdapter :: NewAdapter(policyFile));
        }

        /**
         * Enforcer initializes an enforcer with a database adapter.
         *
         * @param model_path the path of the model file.
         * @param adapter the adapter.
         */
        static Enforcer* NewEnforcer(string model_path, Adapter* adapter) {
            Enforcer* e = NewEnforcer(Model :: NewModelFromFile(model_path), adapter);
            e->model_path = model_path;
            return e;
        }

        /**
         * Enforcer initializes an enforcer with a model and a database adapter.
         *
         * @param m the model.
         * @param adapter the adapter.
         */
        static Enforcer* NewEnforcer(Model* m, Adapter* adapter) {
            Enforcer* e = new Enforcer;
            e->adapter = adapter;
            e->watcher = NULL;

            e->model = m;
            e->model->PrintModel();
            e->func_map.LoadFunctionMap();

            e->initialize();

            if (e->adapter != NULL) {
                e->LoadPolicy();
            }
            return e;
        }

        /**
         * Enforcer initializes an enforcer with a model.
         *
         * @param m the model.
         */
        static Enforcer* NewEnforcer(Model* m) {
            return NewEnforcer(m, NULL);
        }

        /**
         * Enforcer initializes an enforcer with a model file.
         *
         * @param model_path the path of the model file.
         */
        static Enforcer* NewEnforcer(string model_path) {
            return NewEnforcer(model_path, "");
        }

        /**
         * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
         *
         * @param model_path the path of the model file.
         * @param policyFile the path of the policy file.
         * @param enableLog whether to enable Casbin's log.
         */
        static Enforcer* NewEnforcer(string model_path, string policyFile, bool enableLog) {
            Enforcer* e = NewEnforcer(model_path, FileAdapter :: NewAdapter(policyFile));
            // e.EnableLog(enableLog);
            return e;
        }


        // InitWithFile initializes an enforcer with a model file and a policy file.
        void InitWithFile(string model_path, string policyPath) {
            Adapter* a = FileAdapter::NewAdapter(policyPath);
            this->InitWithAdapter(model_path, a);
        }

        // InitWithAdapter initializes an enforcer with a database adapter.
        void InitWithAdapter(string model_path, Adapter* adapter) {
            Model* m = Model :: NewModelFromFile(model_path);

            this->InitWithModelAndAdapter(m, adapter);

            this->model_path = model_path;
        }

        // InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
        void InitWithModelAndAdapter(Model* m, Adapter* adapter) {
            this->adapter = adapter;

            this->model = m;
            this->model->PrintModel();
            this->func_map.LoadFunctionMap();

            this->initialize();

            // Do not initialize the full policy when using a filtered adapter
            if(this->adapter != NULL && !this->adapter->IsFiltered()) 
                this->LoadPolicy();
        }

        void initialize() {
            this->rm = DefaultRoleManager :: NewRoleManager(10);
            this->eft = DefaultEffector :: NewDefaultEffector();
            this->watcher = NULL;

            this->enabled = true;
            this->auto_save = true;
            this->auto_build_role_links = true;
            this->auto_notify_watcher = true;
        }

        // LoadModel reloads the model from the model CONF file.
        // Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
        void LoadModel() {
            this->model = Model :: NewModelFromFile(this->model_path);

            this->model->PrintModel();
            this->func_map.LoadFunctionMap();

            this->initialize();
        }

        // GetModel gets the current model.
        Model* GetModel() {
            return this->model;
        }

        // SetModel sets the current model.
        void SetModel(Model* m) {
            this->model = m;
            this->func_map.LoadFunctionMap();

            this->initialize();
        }

        // GetAdapter gets the current adapter.
        Adapter* GetAdapter() {
            return this->adapter;
        }

        // SetAdapter sets the current adapter.
        void SetAdapter(Adapter* adapter) {
            this->adapter = adapter;
        }

        // SetWatcher sets the current watcher.
        void SetWatcher(Watcher* watcher) {
            this->watcher = watcher;
            auto func = [&, this](string str) {
                this->LoadPolicy();
            };
            watcher->SetUpdateCallback(func);
        }

        // GetRoleManager gets the current role manager.
        RoleManager* GetRoleManager() {
            return this->rm;
        }

        // SetRoleManager sets the current role manager.
        void SetRoleManager(RoleManager* rm) {
            this->rm = rm;
        }

        // SetEffector sets the current effector.
        void SetEffector(Effector* eft) {
            this->eft = eft;
        }

        // ClearPolicy clears all policy.
        void ClearPolicy() {
            this->model->ClearPolicy();
        }

        // LoadPolicy reloads the policy from file/database.
        void LoadPolicy() {
            this->model->ClearPolicy();
            this->adapter->LoadPolicy(this->model);

            this->model->PrintPolicy();

            if(this->auto_build_role_links) {
                this->BuildRoleLinks();
            }
        }

        //LoadFilteredPolicy reloads a filtered policy from file/database.
        void LoadFilteredPolicy(Filter* filter) {
            this->model->ClearPolicy();

            FilteredAdapter* filteredAdapter;

            if (this->adapter->IsFiltered()) {
                void* adapter = this->adapter;
                filteredAdapter = (FilteredAdapter*)adapter;
            }
            else
                throw CasbinAdapterException("filtered policies are not supported by this adapter");

            filteredAdapter->LoadFilteredPolicy(this->model, filter);

            this->model->PrintPolicy();
            if(this->auto_build_role_links)
                this->BuildRoleLinks();
        }

        // IsFiltered returns true if the loaded policy has been filtered.
        bool IsFiltered() {
            return this->adapter->IsFiltered();
        }

        // SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
        void SavePolicy() {
            if(this->IsFiltered())
                throw CasbinEnforcerException("cannot save a filtered policy");

            this->adapter->SavePolicy(this->model);

            if(this->watcher != NULL){
                if (IsInstanceOf<WatcherEx>(this->watcher)){
                    void* watcher = this->watcher;
                    ((WatcherEx*)watcher)->UpdateSavePolicy(this->model);
                }
                else
                    return this->watcher->Update();
            }
        }

        // EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
        void EnableEnforce(bool enable) {
            this->enabled = enable;
        }

        // EnableLog changes whether Casbin will log messages to the Logger.
        // void EnableLog(bool enable) {
            // log.GetLogger().EnableLog(enable);
        // }

        // EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
        void EnableAutoNotifyWatcher(bool enable) {
            this->auto_notify_watcher = enable;
        }

        // EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
        void EnableAutoSave(bool auto_save) {
            this->auto_save = auto_save;
        }

        // EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
        void EnableAutoBuildRoleLinks(bool auto_build_role_links) {
            this->auto_build_role_links = auto_build_role_links;
        }

        // BuildRoleLinks manually rebuild the role inheritance relations.
        void BuildRoleLinks() {
            this->rm->Clear();

            this->model->BuildRoleLinks(this->rm);
        }

        // BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
        void BuildIncrementalRoleLinks(policy_op op, string p_type, vector<vector<string>> rules) {
            return this->model->BuildIncrementalRoleLinks(this->rm, op, "g", p_type, rules);
        }

        // Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
        bool Enforce(Scope scope) {
            return this->enforce("", scope);
        }

        // EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
        bool EnforceWithMatcher(string matcher, Scope scope) {
            return this->enforce(matcher, scope);
        }

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
        void AddFunction(string name, Function);

        /*RBAC API member functions.*/
        vector<string> GetRolesForUser(string name);
        vector<string> GetUsersForRole(string name);
        bool HasRoleForUser(string name, string role);
        bool AddRoleForUser(string user, string role);
        bool AddPermissionForUser(string user, vector<string> permission);
        bool DeletePermissionForUser(string user, vector<string> permission);
        bool DeletePermissionsForUser(string user);
        vector<vector<string>> GetPermissionsForUser(string user);
        bool HasPermissionForUser(string user, vector<string> permission);
        vector<string> GetImplicitRolesForUser(string name, vector<string> domain);
        vector<vector<string>> GetImplicitPermissionsForUser(string user, vector<string> domain);
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
        vector<string> GetUsersForRoleInDomain(string name, string domain);
        vector<string> GetRolesForUserInDomain(string name, string domain);
        vector<vector<string>> GetPermissionsForUserInDomain(string user, string domain);
        bool AddRoleForUserInDomain(string user, string role, string domain);
        bool DeleteRoleForUserInDomain(string user, string role, string domain);

};

#endif