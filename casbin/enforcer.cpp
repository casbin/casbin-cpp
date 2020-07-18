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

#pragma once

#include "pch.h"

#include <algorithm>

#include "./enforcer.h"
#include "./persist/watcher_ex.h"
#include "./persist/file_adapter/file_adapter.h"
#include "./rbac/default_role_manager.h"
#include "./effect/default_effector.h"
#include "./exception/casbin_adapter_exception.h"
#include "./exception/casbin_enforcer_exception.h"
#include "./util/util.h"

// enforce use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool Enforcer :: enforce(string matcher, Scope scope) {
    // TODO
    // defer func() {
    // 	if err := recover(); err != nil {
    // 		fmt.Errorf("panic: %v", err)
    // 	}
    // }()

    this->func_map.scope = scope;
    this->func_map.LoadFunctionMap();

    if(!this->enabled)
        return true;

    // for(unordered_map <string, Function> :: iterator it = this->fm.fmap.begin() ; it != this->fm.fmap.end() ; it++)
    // 	this->fm.AddFunction(it->first, it->second);

    string exp_string;
    if(matcher == "")
        exp_string = this->model->m["m"].assertion_map["m"]->value;
    else
        exp_string = matcher;


    unordered_map <string, RoleManager*> rm_map;
    bool ok = this->model->m.find("g") != this->model->m.end();

    if(ok) {
        for(unordered_map <string, Assertion*> :: iterator it = this->model->m["g"].assertion_map.begin() ; it != this->model->m["g"].assertion_map.end() ; it++){
            RoleManager* rm = it->second->rm;
            int char_count = int(count(it->second->value.begin(), it->second->value.end(), '_'));
            int index = int(exp_string.find((it->first)+"("));
            if(index != string::npos)
                exp_string.insert(index+(it->first+"(").length(), "rm, ");
            PushPointer(this->func_map.scope, (void *)rm, "rm");
            this->func_map.AddFunction(it->first, GFunction, char_count + 1);
        }
    }

    unordered_map <string, int> p_int_tokens;
    for(int i = 0 ; i < this->model->m["p"].assertion_map["p"]->tokens.size() ; i++)
        p_int_tokens[this->model->m["p"].assertion_map["p"]->tokens[i]] = i;

    vector <string> p_tokens = this->model->m["p"].assertion_map["p"]->tokens;

    int policy_len = int(this->model->m["p"].assertion_map["p"]->policy.size());

    vector <Effect> policy_effects(policy_len, Effect :: Indeterminate);
    vector <float> matcher_results;

    if(policy_len != 0) {
        if(this->model->m["r"].assertion_map["r"]->tokens.size() != this->func_map.GetRLen())
            return false;

        //TODO
        for( int i = 0 ; i < policy_len ; i++){
            // log.LogPrint("Policy Rule: ", pvals)
            vector<string> p_vals = this->model->m["p"].assertion_map["p"]->policy[i];
            if(this->model->m["p"].assertion_map["p"]->tokens.size() != p_vals.size())
                return false;

            PushObject(this->func_map.scope, "p");
            for(int j = 0 ; j < p_tokens.size() ; j++){
                int index = int(p_tokens[j].find("_"));
                string token = p_tokens[j].substr(index+1);
                PushStringPropToObject(this->func_map.scope, "p", p_vals[j], token);
            }

            this->func_map.Evaluate(exp_string);
            
            //TODO
            // log.LogPrint("Result: ", result)
            if(CheckType(this->func_map.scope) == Type :: Bool){
                bool result = GetBoolean(this->func_map.scope);
                if(!result) {
                    policy_effects[i] = Effect :: Indeterminate;
                    continue;
                }
            }
            else if(CheckType(this->func_map.scope) == Type :: Float){
                bool result = GetFloat(this->func_map.scope);
                if(result == 0) {
                    policy_effects[i] = Effect :: Indeterminate;
                    continue;
                } else
                    matcher_results[i] = result;
            }
            else
                return false;

            bool is_p_eft = p_int_tokens.find("p_eft") != p_int_tokens.end();
            if(is_p_eft) {
                int j = p_int_tokens["p_eft"];
                string eft = p_vals[j];
                if(eft == "allow")
                    policy_effects[i] = Effect :: Allow;
                else if(eft == "deny")
                    policy_effects[i] = Effect :: Deny;
                else
                    policy_effects[i] = Effect :: Indeterminate;
            }
            else
                policy_effects[i] = Effect :: Allow;

            if(this->model->m["e"].assertion_map["e"]->value == "priority(p_eft) || deny")
                break;
        }
    } else {
        bool isValid = this->func_map.Evaluate(exp_string);
        if(!isValid)
            return false;
        bool result = this->func_map.GetBooleanResult();

        //TODO
        // log.LogPrint("Result: ", result)
        if(result)
            policy_effects.push_back(Effect::Allow);
        else
            policy_effects.push_back(Effect::Indeterminate);
    }

    //TODO
    // log.LogPrint("Rule Results: ", policyEffects)

    bool result = this->eft->MergeEffects(this->model->m["e"].assertion_map["e"]->value, policy_effects, matcher_results);

    return result;
}

/**
 * Enforcer is the default constructor.
 */
unique_ptr<Enforcer> Enforcer ::NewEnforcer() {
    unique_ptr<Enforcer> e = unique_ptr<Enforcer>(new Enforcer());
    return move(e);
}

/**
 * Enforcer initializes an enforcer with a model file and a policy file.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 */
unique_ptr<Enforcer> Enforcer :: NewEnforcer(string model_path, string policyFile) {
    return move(NewEnforcer(model_path, shared_ptr<FileAdapter>(FileAdapter :: NewAdapter(policyFile))));
}

/**
 * Enforcer initializes an enforcer with a database adapter.
 *
 * @param model_path the path of the model file.
 * @param adapter the adapter.
 */
unique_ptr<Enforcer> Enforcer :: NewEnforcer(string model_path, shared_ptr<Adapter> adapter) {
    unique_ptr<Enforcer> e = NewEnforcer(shared_ptr<Model>(Model :: NewModelFromFile(model_path)), adapter);
    e->model_path = model_path;
    return move(e);
}

/**
 * Enforcer initializes an enforcer with a model and a database adapter.
 *
 * @param m the model.
 * @param adapter the adapter.
 */
unique_ptr<Enforcer> Enforcer :: NewEnforcer(shared_ptr<Model> m, shared_ptr<Adapter> adapter) {
  unique_ptr<Enforcer> e = unique_ptr<Enforcer>(new Enforcer());
    e->adapter = adapter;
    e->watcher = NULL;

    e->model = m;
    e->model->PrintModel();
    e->func_map.LoadFunctionMap();

    e->Initialize();

    if (e->adapter->file_path != "") {
        e->LoadPolicy();
    }
    return move(e);
}

/**
 * Enforcer initializes an enforcer with a model.
 *
 * @param m the model.
 */
unique_ptr<Enforcer> Enforcer ::NewEnforcer(shared_ptr<Model> m) {
    return move(NewEnforcer(m, NULL));
}

/**
 * Enforcer initializes an enforcer with a model file.
 *
 * @param model_path the path of the model file.
 */
unique_ptr<Enforcer> Enforcer ::NewEnforcer(string model_path) {
    return move(NewEnforcer(model_path, ""));
}

/**
 * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 * @param enableLog whether to enable Casbin's log.
 */
unique_ptr<Enforcer> Enforcer :: NewEnforcer(string model_path, string policyFile, bool enableLog) {
    unique_ptr<Enforcer> e = NewEnforcer(model_path, shared_ptr<FileAdapter>(FileAdapter :: NewAdapter(policyFile)));
    // e.EnableLog(enableLog);
    return move(e);
}


// InitWithFile initializes an enforcer with a model file and a policy file.
void Enforcer :: InitWithFile(string model_path, string policyPath) {
    shared_ptr<Adapter> a = shared_ptr<FileAdapter>(FileAdapter::NewAdapter(policyPath));
    this->InitWithAdapter(model_path, a);
}

// InitWithAdapter initializes an enforcer with a database adapter.
void Enforcer :: InitWithAdapter(string model_path, shared_ptr<Adapter> adapter) {
    shared_ptr<Model> m =shared_ptr<Model>(Model :: NewModelFromFile(model_path));

    this->InitWithModelAndAdapter(m, adapter);

    this->model_path = model_path;
}

// InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
void Enforcer :: InitWithModelAndAdapter(shared_ptr<Model> m, shared_ptr<Adapter> adapter) {
    this->adapter = adapter;

    this->model = m;
    this->model->PrintModel();
    this->func_map.LoadFunctionMap();

    this->Initialize();

    // Do not initialize the full policy when using a filtered adapter
    if(this->adapter != NULL && !this->adapter->IsFiltered()) 
        this->LoadPolicy();
}

void Enforcer :: Initialize() {
    this->rm = shared_ptr<DefaultRoleManager>(DefaultRoleManager :: NewRoleManager(10));
    this->eft = shared_ptr<DefaultEffector>(DefaultEffector :: NewDefaultEffector());
    this->watcher = NULL;

    this->enabled = true;
    this->auto_save = true;
    this->auto_build_role_links = true;
    this->auto_notify_watcher = true;
}

// LoadModel reloads the model from the model CONF file.
// Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
void Enforcer :: LoadModel() {
    this->model = shared_ptr<Model>(Model ::NewModelFromFile(this->model_path));

    this->model->PrintModel();
    this->func_map.LoadFunctionMap();

    this->Initialize();
}

// GetModel gets the current model.
shared_ptr<Model> Enforcer :: GetModel() {
    return this->model;
}

// SetModel sets the current model.
void Enforcer :: SetModel(shared_ptr<Model> m) {
    this->model = m;
    this->func_map.LoadFunctionMap();

    this->Initialize();
}

// GetAdapter gets the current adapter.
shared_ptr<Adapter> Enforcer::GetAdapter() {
    return this->adapter;
}

// SetAdapter sets the current adapter.
void Enforcer::SetAdapter(shared_ptr<Adapter> adapter) {
    this->adapter = adapter;
}

// SetWatcher sets the current watcher.
void Enforcer :: SetWatcher(shared_ptr<Watcher> watcher) {
    this->watcher = watcher;
    auto func = [&, this](string str) {
        this->LoadPolicy();
    };
    watcher->SetUpdateCallback(func);
}

// GetRoleManager gets the current role manager.
shared_ptr<RoleManager> Enforcer ::GetRoleManager() {
    return this->rm;
}

// SetRoleManager sets the current role manager.
void Enforcer :: SetRoleManager(shared_ptr<RoleManager> rm) {
    this->rm = rm;
}

// SetEffector sets the current effector.
void Enforcer :: SetEffector(shared_ptr<Effector> eft) {
    this->eft = eft;
}

// ClearPolicy clears all policy.
void Enforcer :: ClearPolicy() {
    this->model->ClearPolicy();
}

// LoadPolicy reloads the policy from file/database.
void Enforcer :: LoadPolicy() {
    this->model->ClearPolicy();
    this->adapter->LoadPolicy(this->model.get());
    this->model->PrintPolicy();

    if(this->auto_build_role_links) {
        this->BuildRoleLinks();
    }
}

//LoadFilteredPolicy reloads a filtered policy from file/database.
template<typename Filter>
void Enforcer :: LoadFilteredPolicy(Filter filter) {
    this->model->ClearPolicy();

    FilteredAdapter* filteredAdapter;

    if (this->adapter->IsFiltered()) {
        void* adapter = this->adapter.get();
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
bool Enforcer :: IsFiltered() {
    return this->adapter->IsFiltered();
}

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
void Enforcer :: SavePolicy() {
    if(this->IsFiltered())
        throw CasbinEnforcerException("cannot save a filtered policy");

    this->adapter->SavePolicy(this->model.get());

    if(this->watcher != NULL){
        if (IsInstanceOf<WatcherEx>(this->watcher.get())) {
            void* watcher = this->watcher.get();
            ((WatcherEx*)watcher)->UpdateForSavePolicy(this->model.get());
        }
        else
            return this->watcher->Update();
    }
}

// EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
void Enforcer :: EnableEnforce(bool enable) {
    this->enabled = enable;
}

// EnableLog changes whether Casbin will log messages to the Logger.
// void Enforcer :: EnableLog(bool enable) {
    // log.GetLogger().EnableLog(enable);
// }

// EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
void Enforcer :: EnableAutoNotifyWatcher(bool enable) {
    this->auto_notify_watcher = enable;
}

// EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
void Enforcer :: EnableAutoSave(bool auto_save) {
    this->auto_save = auto_save;
}

// EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
void Enforcer :: EnableAutoBuildRoleLinks(bool auto_build_role_links) {
    this->auto_build_role_links = auto_build_role_links;
}

// BuildRoleLinks manually rebuild the role inheritance relations.
void Enforcer :: BuildRoleLinks() {
    this->rm->Clear();

    this->model->BuildRoleLinks(this->rm.get());
}

// BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
void Enforcer :: BuildIncrementalRoleLinks(policy_op op, string p_type, vector<vector<string>> rules) {
    return this->model->BuildIncrementalRoleLinks(this->rm.get(), op, "g", p_type, rules);
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
bool Enforcer :: Enforce(Scope scope) {
    return this->EnforceWithMatcher("", scope);
}

// Enforce with a vector param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
bool Enforcer::Enforce(vector<string> params) {
    return this->EnforceWithMatcher("", params);
}

// Enforce with a map param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
bool Enforcer::Enforce(unordered_map<string, string> params) {
    return this->EnforceWithMatcher("", params);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool Enforcer :: EnforceWithMatcher(string matcher, Scope scope) {
    return this->enforce(matcher, scope);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool Enforcer::EnforceWithMatcher(string matcher, vector<string> params) {
    vector <string> r_tokens = this->model->m["r"].assertion_map["r"]->tokens;

    int r_cnt = int(r_tokens.size());
    int cnt = int(params.size());

    if (cnt != r_cnt)
        return false;

    Scope scope = InitializeScope();
    PushObject(scope, "r");

    for (int i = 0; i < cnt; i++) {
        PushStringPropToObject(scope, "r", params[i], r_tokens[i].substr(2, r_tokens[i].size() - 2));
    }

    return this->enforce(matcher, scope);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool Enforcer::EnforceWithMatcher(string matcher, unordered_map<string, string> params) {
    Scope scope = InitializeScope();
    PushObject(scope, "r");

    for (auto r : params) {
        PushStringPropToObject(scope, "r", r.second, r.first);
    }

    return this->enforce(matcher, scope);
}