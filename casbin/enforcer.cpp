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

#include "casbin/pch.h"

#ifndef ENFORCER_CPP
#define ENFORCER_CPP


#include <algorithm>

#include "casbin/enforcer.h"
#include "casbin/persist/watcher_ex.h"
#include "casbin/persist/file_adapter/file_adapter.h"
#include "casbin/persist/file_adapter/batch_file_adapter.h"
#include "casbin/rbac/default_role_manager.h"
#include "casbin/effect/default_effector.h"
#include "casbin/exception/casbin_adapter_exception.h"
#include "casbin/exception/casbin_enforcer_exception.h"
#include "casbin/util/util.h"

namespace casbin {

// enforce use a custom matcher to decides whether a "subject" can access a "object" 
// with the operation "action", input parameters are usually: (matcher, sub, obj, act), 
// use model matcher by default when matcher is "".
bool Enforcer::m_enforce(const std::string& matcher, std::shared_ptr<IEvaluator> evalator) {
    m_func_map.evalator = evalator;
    m_func_map.evalator->func_list.clear();
    m_func_map.LoadFunctionMap();

    if(!m_enabled)
        return true;

    std::string exp_string;
    if(matcher == "")
        exp_string = m_model->m["m"].assertion_map["m"]->value;
    else
        exp_string = matcher;


    // std::unordered_map<std::string, std::shared_ptr<RoleManager>> rm_map;
    bool ok = m_model->m.find("g") != m_model->m.end();

    if(ok) {
        for (auto [assertion_name, assertion] : m_model->m["g"].assertion_map) {
            std::shared_ptr<RoleManager>& rm = assertion->rm;

                int char_count = static_cast<int>(std::count(assertion->value.begin(), assertion->value.end(), '_'));
                size_t index = exp_string.find(assertion_name + "(");

                if (dynamic_cast<DuktapeEvaluator*>(m_func_map.evalator.get()) != nullptr) {
                    if (index != std::string::npos)
                        exp_string.insert(index + assertion_name.length() + 1, "rm, ");

                    m_func_map.evalator->LoadGFunction(rm, assertion_name, char_count + 1);
                } else {
                    m_func_map.evalator->LoadGFunction(rm, assertion_name, char_count);
                }
        }
    }

    // apply function map to current scope.
    // for(auto func : m_user_func_list)
    //     m_func_map.AddFunction(std::get<0>(func), std::get<1>(func), std::get<2>(func));

    bool hasEval = HasEval(exp_string);
    
    std::unordered_map<std::string, int> p_int_tokens;
    std::vector<std::string>& p_tokens = m_model->m["p"].assertion_map["p"]->tokens;
    p_int_tokens.reserve(p_tokens.size());

    for (int i = 0; i < p_tokens.size(); i++)
        p_int_tokens[p_tokens[i]] = i;

    std::vector<std::vector<std::string>>& p_policy = m_model->m["p"].assertion_map["p"]->policy;
    size_t policy_len = p_policy.size();

    std::vector<Effect> policy_effects(policy_len, Effect::Indeterminate);
    std::vector<float> matcher_results(policy_len, 0.0f);

    if(policy_len != 0) {
        // if(m_model->m["r"].assertion_map["r"]->tokens.size() != m_func_map.GetRLen())
        //     return false;

        //TODO
        for(int i = 0 ; i < policy_len ; i++) {
            std::vector<std::string>& p_vals = m_model->m["p"].assertion_map["p"]->policy[i];
            m_log.LogPrint("Policy Rule: ", p_vals);
            if(p_tokens.size() != p_vals.size())
                return false;
            m_func_map.evalator->Clean(m_model->m["p"]);
            m_func_map.evalator->InitialObject("p");
            for(int j = 0 ; j < p_tokens.size() ; j++) {
                size_t index = p_tokens[j].find("_");
                std::string token = p_tokens[j].substr(index + 1);
                m_func_map.evalator->PushObjectString("p", token, p_vals[j]);
            }

            if(hasEval) {
                auto ruleNames = GetEvalValue(exp_string);
                std::unordered_map<std::string, std::string> replacements;
                for(auto& ruleName: ruleNames) {
                    auto ruleNameCpy = EscapeAssertion(ruleName);

                    bool ok = p_int_tokens.find(ruleNameCpy) != p_int_tokens.end();
                    if (ok) {
                        int idx = p_int_tokens[ruleNameCpy];
                        replacements[ruleName] = p_vals[idx];
                    } else {
                        m_log.LogPrint("please make sure rule exists in policy when using eval() in matcher");
                        return false;
                    }
                }

                auto expWithRule = ReplaceEvalWithMap(exp_string, replacements);
                m_func_map.Evaluate(expWithRule);

            } else {

                m_func_map.Evaluate(exp_string);
            }

            //TODO
            // log.LogPrint("Result: ", result)
            if (m_func_map.evalator->CheckType() == Type::Bool) {
                bool result = m_func_map.evalator->GetBoolen();
                if (!result) {
                    policy_effects[i] = Effect::Indeterminate;
                    continue;
                }
            } else if (m_func_map.evalator->CheckType() == Type::Float){
                float result = m_func_map.evalator->GetFloat();
                if(result == 0.0) {
                    policy_effects[i] = Effect::Indeterminate;
                    continue;
                } else
                    matcher_results[i] = result;
            }
            else
                return false;

            bool is_p_eft = p_int_tokens.find("p_eft") != p_int_tokens.end();
            if(is_p_eft) {
                int j = p_int_tokens["p_eft"];
                std::string eft = p_vals[j];
                if(eft == "allow")
                    policy_effects[i] = Effect::Allow;
                else if(eft == "deny")
                    policy_effects[i] = Effect::Deny;
                else
                    policy_effects[i] = Effect::Indeterminate;
            }
            else
                policy_effects[i] = Effect::Allow;

            if(m_model->m["e"].assertion_map["e"]->value == "priority(p_eft) || deny")
                break;
        }
    } else {
        // Push initial value for p in symbol table
        // If p don't in symbol table, the evaluate result will be invalid.
        m_func_map.evalator->Clean(m_model->m["p"]);
        m_func_map.evalator->InitialObject("p");
        for(int j = 0 ; j < p_tokens.size() ; j++) {
            size_t index = p_tokens[j].find("_");
            std::string token = p_tokens[j].substr(index + 1);
            m_func_map.evalator->PushObjectString("p", token, "");
        }

        bool isvalid = m_func_map.Evaluate(exp_string);
        if (!isvalid) {
            return false;
        }
        bool result = m_func_map.evalator->GetBoolen();
        //TODO
        m_log.LogPrint("Result: ", result);
        if (result)
            policy_effects.push_back(Effect::Allow);
        else
            policy_effects.push_back(Effect::Indeterminate);
    }

    //TODO
    m_log.LogPrint("Rule Results: ", policy_effects);

    bool result = m_eft->MergeEffects(m_model->m["e"].assertion_map["e"]->value, policy_effects, matcher_results);

    return result;
}

/**
 * Enforcer is the default constructor.
 */
Enforcer ::Enforcer() {
}

/**
 * Enforcer initializes an enforcer with a model file and a policy file.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 */
Enforcer ::Enforcer(const std::string& model_path, const std::string& policy_file)
    : Enforcer(model_path, std::make_shared<BatchFileAdapter>(policy_file)) {
}   

/**
 * Enforcer initializes an enforcer with a database adapter.
 *
 * @param model_path the path of the model file.
 * @param adapter the adapter.
 */
Enforcer ::Enforcer(const std::string& model_path, std::shared_ptr<Adapter> adapter)
    : Enforcer(std::make_shared<Model>(model_path), adapter) {
    m_model_path = model_path;
}

/**
 * Enforcer initializes an enforcer with a model and a database adapter.
 *
 * @param m the model.
 * @param adapter the adapter.
 */
Enforcer::Enforcer(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter)
    : m_adapter(adapter), m_watcher(nullptr), m_model(m) {
    m_model->PrintModel();

    this->Initialize();

    if (m_adapter && m_adapter->file_path != "")
        this->LoadPolicy();
}

/**
 * Enforcer initializes an enforcer with a model.
 *
 * @param m the model.
 */
Enforcer::Enforcer(const std::shared_ptr<Model>& m) : Enforcer(m, NULL) {
}

/**
 * Enforcer initializes an enforcer with a model file.
 *
 * @param model_path the path of the model file.
 */
Enforcer ::Enforcer(const std::string& model_path): Enforcer(model_path, "") {
}

/**
 * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 * @param enableLog whether to enable Casbin's log.
 */
Enforcer::Enforcer(const std::string& model_path, const std::string& policy_file, bool enable_log)
    : Enforcer(model_path, std::make_shared<BatchFileAdapter>(policy_file)) {
    this->EnableLog(enable_log);
}


// InitWithFile initializes an enforcer with a model file and a policy file.
void Enforcer::InitWithFile(const std::string& model_path, const std::string& policy_path) {
    std::shared_ptr<Adapter> a = std::make_shared<BatchFileAdapter>(policy_path);
    this->InitWithAdapter(model_path, a);
}

// InitWithAdapter initializes an enforcer with a database adapter.
void Enforcer::InitWithAdapter(const std::string& model_path, std::shared_ptr<Adapter> adapter) {
    std::shared_ptr<Model> m = Model::NewModelFromFile(model_path);

    this->InitWithModelAndAdapter(m, adapter);

    m_model_path = model_path;
}

// InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
void Enforcer::InitWithModelAndAdapter(const std::shared_ptr<Model>& m, std::shared_ptr<Adapter> adapter) {
    m_adapter = adapter;

    m_model = m;
    m_model->PrintModel();
    m_func_map.LoadFunctionMap();

    this->Initialize();

    // Do not initialize the full policy when using a filtered adapter
    if(m_adapter != NULL && !m_adapter->IsFiltered()) 
        this->LoadPolicy();
}

void Enforcer::Initialize() {
    this->rm = std::make_shared<DefaultRoleManager>(10);
    m_eft = std::make_shared<DefaultEffector>();
    m_watcher = nullptr;
    m_evalator = nullptr;

    m_enabled = true;
    m_auto_save = true;
    m_auto_build_role_links = true;
    m_auto_notify_watcher = true;
}

/**
 * Destructor of Enforcer
 * 
 * @step: Release the memory of Enforcer->m_scope
*/
Enforcer::~Enforcer() {}

// LoadModel reloads the model from the model CONF file.
// Because the policy is attached to a model, so the policy is invalidated and needs 
// to be reloaded by calling LoadPolicy().
void Enforcer::LoadModel() {
    m_model = Model::NewModelFromFile(m_model_path);

    m_model->PrintModel();
    m_func_map.LoadFunctionMap();

    this->Initialize();
}

// GetModel gets the current model.
std::shared_ptr<Model> Enforcer::GetModel() {
    return m_model;
}

// SetModel sets the current model.
void Enforcer::SetModel(const std::shared_ptr<Model>& m) {
    m_model = m;
    m_func_map.LoadFunctionMap();

    this->Initialize();
}

// GetAdapter gets the current adapter.
std::shared_ptr<Adapter> Enforcer::GetAdapter() {
    return m_adapter;
}

// SetAdapter sets the current adapter.
void Enforcer::SetAdapter(std::shared_ptr<Adapter> adapter) {
    m_adapter = adapter;
}

// SetWatcher sets the current watcher.
void Enforcer::SetWatcher(std::shared_ptr<Watcher> watcher) {
    m_watcher = watcher;
    auto func = [&, this](std::string str) {
        this->LoadPolicy();
    };
    watcher->SetUpdateCallback(func);
}

// SetWatcher sets the current evaluator.
void Enforcer::SetEvaluator(std::shared_ptr<IEvaluator> evaluator) {
    this->m_evalator = evaluator;
}

// GetRoleManager gets the current role manager.
std::shared_ptr<RoleManager> Enforcer ::GetRoleManager() {
    return this->rm;
}

// SetRoleManager sets the current role manager.
void Enforcer::SetRoleManager(std::shared_ptr<RoleManager>& rm) {
    this->rm = rm;
}

// SetEffector sets the current effector.
void Enforcer::SetEffector(std::shared_ptr<Effector> eft) {
    m_eft = eft;
}

// ClearPolicy clears all policy.
void Enforcer::ClearPolicy() {
    m_model->ClearPolicy();
}

// LoadPolicy reloads the policy from file/database.
void Enforcer::LoadPolicy() {
    this->ClearPolicy();
    m_adapter->LoadPolicy(m_model);
    m_model->PrintPolicy();

    if(m_auto_build_role_links) {
        this->BuildRoleLinks();
    }
}

//LoadFilteredPolicy reloads a filtered policy from file/database.
template<typename Filter>
void Enforcer::LoadFilteredPolicy(Filter filter) {
    this->ClearPolicy();

    std::shared_ptr<FilteredAdapter> filtered_adapter;

    if (m_adapter->IsFiltered())
        filtered_adapter = std::dynamic_pointer_cast<FilteredAdapter>(m_adapter);
    else
        throw CasbinAdapterException("filtered policies are not supported by this adapter");

    filtered_adapter->LoadFilteredPolicy(m_model, filter);

    m_model->PrintPolicy();
    if(m_auto_build_role_links)
        this->BuildRoleLinks();
}

// IsFiltered returns true if the loaded policy has been filtered.
bool Enforcer::IsFiltered() {
    return m_adapter->IsFiltered();
}

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
void Enforcer::SavePolicy() {
    if(this->IsFiltered())
        throw CasbinEnforcerException("cannot save a filtered policy");

    m_adapter->SavePolicy(m_model);

    if(m_watcher != NULL){
        if (IsInstanceOf<WatcherEx>(m_watcher.get())) {
            auto watcher = dynamic_cast<WatcherEx*>(m_watcher.get());
            watcher->UpdateForSavePolicy(m_model);
        }
        else
            return m_watcher->Update();
    }
}

// EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, 
// all access will be allowed by the Enforce() function.
void Enforcer::EnableEnforce(bool enable) {
    m_enabled = enable;
}

// EnableLog changes whether Casbin will log messages to the Logger.
void Enforcer::EnableLog(bool enable) {
    m_log.GetLogger().EnableLog(enable);
}

// EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
void Enforcer::EnableAutoNotifyWatcher(bool enable) {
    m_auto_notify_watcher = enable;
}

// EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
void Enforcer::EnableAutoSave(bool auto_save) {
    m_auto_save = auto_save;
}

// EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
void Enforcer::EnableAutoBuildRoleLinks(bool auto_build_role_links) {
    m_auto_build_role_links = auto_build_role_links;
}

// BuildRoleLinks manually rebuild the role inheritance relations.
void Enforcer::BuildRoleLinks() {
    this->rm->Clear();

    m_model->BuildRoleLinks(this->rm);
}

// BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
void Enforcer::BuildIncrementalRoleLinks(policy_op op, const std::string& p_type, const std::vector<std::vector<std::string>>& rules) {
    return m_model->BuildIncrementalRoleLinks(this->rm, op, "g", p_type, rules);
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", 
// input parameters are usually: (sub, obj, act).
bool Enforcer::Enforce(std::shared_ptr<IEvaluator> evalator) {
    return this->EnforceWithMatcher("", evalator);
}

// Enforce with a vector param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
bool Enforcer::Enforce(const DataList& params) {
    return this->EnforceWithMatcher("", params);
}

bool Enforcer::Enforce(const DataVector& params) {
    return this->EnforceWithMatcher("", params);
}

// Enforce with a map param,decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
bool Enforcer::Enforce(const DataMap& params) {
    return this->EnforceWithMatcher("", params);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool Enforcer::EnforceWithMatcher(const std::string& matcher, std::shared_ptr<IEvaluator> evalator) {
    return m_enforce(matcher, evalator);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool Enforcer::EnforceWithMatcher(const std::string& matcher, const DataList& params) {
    const std::vector<std::string>& r_tokens = m_model->m["r"].assertion_map["r"]->tokens;

    size_t r_cnt = r_tokens.size();
    size_t cnt = params.size();

    if (cnt != r_cnt)
        return false;

    if (this->m_evalator == nullptr) {
        this->m_evalator = std::make_shared<DuktapeEvaluator>();
    }

    this->m_evalator->InitialObject("r");

    size_t i = 0;

    for(const Data& param : params) {
        if(const auto string_param = std::get_if<std::string>(&param)) {
            this->m_evalator->PushObjectString("r", r_tokens[i].substr(2, r_tokens[i].size() - 2), *string_param);
        } else if (const auto json_param = std::get_if<std::shared_ptr<nlohmann::json>>(&param)) {
            
            auto data_ptr = *json_param;
            std::string token_name = r_tokens[i].substr(2, r_tokens[i].size() - 2);
            this->m_evalator->PushObjectJson("r", token_name, *data_ptr);

        }
        ++i;
    }

    bool result = m_enforce(matcher, m_evalator);

    if (m_evalator != nullptr) {
        m_evalator->Clean(m_model->m["p"]);
        m_evalator->Clean(m_model->m["r"]);
    }

    return result;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool Enforcer::EnforceWithMatcher(const std::string& matcher, const DataVector& params) {
    const std::vector<std::string>& r_tokens = m_model->m["r"].assertion_map["r"]->tokens;

    size_t r_cnt = r_tokens.size();
    size_t cnt = params.size();

    if (cnt != r_cnt)
        return false;

    if (this->m_evalator == nullptr) {
        auto scope = InitializeScope();
        this->m_evalator = std::make_shared<DuktapeEvaluator>(scope);
    }

    this->m_evalator->InitialObject("r");

    size_t i = 0;

    for(const auto& param : params) {
        if(const auto string_param = std::get_if<std::string>(&param)) {
            this->m_evalator->PushObjectString("r", r_tokens[i].substr(2, r_tokens[i].size() - 2), *string_param);
        } else if (const auto json_param = std::get_if<std::shared_ptr<nlohmann::json>>(&param)) {
            
            auto data_ptr = *json_param;
            std::string token_name = r_tokens[i].substr(2, r_tokens[i].size() - 2);

            this->m_evalator->PushObjectJson("r", token_name, *data_ptr);
        }

        ++i;
    }

    bool result = m_enforce(matcher, m_evalator);

    if (m_evalator != nullptr) {
        m_evalator->Clean(m_model->m["p"]);
        m_evalator->Clean(m_model->m["r"]);
    }

    return result;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" 
// with the operation "action", input parameters are usually: (matcher, sub, obj, act), 
// use model matcher by default when matcher is "".
bool Enforcer::EnforceWithMatcher(const std::string& matcher, const DataMap& params) {
    if (this->m_evalator == nullptr) {
        auto scope = InitializeScope();
        this->m_evalator = std::make_shared<DuktapeEvaluator>(scope);
    }

    this->m_evalator->InitialObject("r");

    for (auto [param_name, param_data] : params) {
        if(const auto string_param = std::get_if<std::string>(&param_data)) {
            this->m_evalator->PushObjectString("r", param_name, *string_param);
        } else if (const auto json_param = std::get_if<std::shared_ptr<nlohmann::json>>(&param_data)) {
            
            auto data_ptr = *json_param;
            this->m_evalator->PushObjectJson("r", param_name, *data_ptr);
        }

    }

    bool result = m_enforce(matcher, m_evalator);

    if (m_evalator != nullptr) {
        m_evalator->Clean(m_model->m["p"]);
        m_evalator->Clean(m_model->m["r"]);
    }

    return result;
}

// BatchEnforce enforce in batches
std::vector<bool> Enforcer::BatchEnforce(const std::initializer_list<DataList>& requests) {
    // Initializing an array for storing results with false
    std::vector<bool> results;
    results.reserve(requests.size());
    for (const auto& request : requests) {
        results.push_back(this->Enforce(request));
    }
    return results;
}

// BatchEnforceWithMatcher enforce with matcher in batches
std::vector<bool> Enforcer::BatchEnforceWithMatcher(const std::string& matcher, const std::initializer_list<DataList>& requests) {
    std::vector<bool> results;
    results.reserve(requests.size());
    for (const auto& request : requests) {
        results.push_back(this->EnforceWithMatcher(matcher, request));
    }
    return results;
}

// clean scope to prepare next enforce
void Enforcer::clean_scope(std::string section_name) {

}

} // namespace casbin

#endif // ENFORCER_CPP
