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

#include "pch.h"

#ifndef ENFORCER_SYNCED_CPP
#define ENFORCER_SYNCED_CPP

#include <mutex>
#include <atomic>
#include <memory>

#include "./enforcer_synced.h"
#include "./persist/watcher.h"
#include "./enforcer_synced.h"
#include "./util/ticker.h"

/**
 * Enforcer is the default constructor.
 */
SyncedEnforcer ::SyncedEnforcer() 
  : autoLoadRunning(false)
{}

/**
 * Enforcer initializes an enforcer with a model file and a policy file.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 */
SyncedEnforcer ::SyncedEnforcer(string model_path, string policy_file)
  : Enforcer(model_path, policy_file), autoLoadRunning(false)
{}

/**
 * Enforcer initializes an enforcer with a database adapter.
 *
 * @param model_path the path of the model file.
 * @param adapter the adapter.
 */
SyncedEnforcer ::SyncedEnforcer(string model_path, shared_ptr<Adapter> adapter)
  : Enforcer(model_path,adapter), autoLoadRunning(false)
{}

/**
 * Enforcer initializes an enforcer with a model and a database adapter.
 *
 * @param m the model.
 * @param adapter the adapter.
 */
SyncedEnforcer :: SyncedEnforcer(shared_ptr<Model> m, shared_ptr<Adapter> adapter)
  : Enforcer(m, adapter), autoLoadRunning(false)
{}

/**
 * Enforcer initializes an enforcer with a model.
 *
 * @param m the model.
 */
SyncedEnforcer ::SyncedEnforcer(shared_ptr<Model> m)
  : Enforcer(m), autoLoadRunning(false)
{}

/**
 * Enforcer initializes an enforcer with a model file.
 *
 * @param model_path the path of the model file.
 */
SyncedEnforcer ::SyncedEnforcer(string model_path)
  : Enforcer(model_path), autoLoadRunning(false)
{}

/**
 * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 * @param enableLog whether to enable Casbin's log.
 */
SyncedEnforcer :: SyncedEnforcer(string model_path, string policy_file, bool enable_log)
  : Enforcer(model_path, policy_file, enable_log), autoLoadRunning(false) 
{}

// SyncedEnforcer::SyncedEnforcer(const SyncedEnforcer& ce)
//    : Enforcer(ce), autoLoadRunning(ce.autoLoadRunning)
// {}

// SyncedEnforcer::SyncedEnforcer(SyncedEnforcer&& ce)
//   : Enforcer(ce), autoLoadRunning(ce->autoLoadRunning)
// {}


void SyncedEnforcer ::LoadPolicyWrapper() {
  Enforcer::LoadPolicy();
  ++n;
}

// StartAutoLoadPolicy starts a thread that will go through every specified duration call LoadPolicy
void SyncedEnforcer ::StartAutoLoadPolicy(std::chrono::duration<int64_t, std::nano> t) {
  if(IsAutoLoadingRunning())
    return;
  autoLoadRunning = true;
  std::function<void()> onTick = [this]() {
    Enforcer::LoadPolicy();
    ++n;
  };
  ticker = std::unique_ptr<Ticker>(new Ticker(onTick, t));
  n = 1;
  ticker->start();
}

// IsAutoLoadingRunning check if SyncedEnforcer is auto loading policies
inline bool SyncedEnforcer ::IsAutoLoadingRunning() {
  return autoLoadRunning;
}

// StopAutoLoadPolicy causes the thread to exit
void SyncedEnforcer ::StopAutoLoadPolicy() {
  ticker->stop();
}

string SyncedEnforcer ::UpdateWrapper() {
  LoadPolicy();
  return "";
}

// SetWatcher sets the current watcher.
void SyncedEnforcer ::SetWatcher(shared_ptr<Watcher> w){
  watcher = w;
  return watcher->SetUpdateCallback(&SyncedEnforcer::UpdateWrapper);
}

// LoadModel reloads the model from the model CONF file.
void SyncedEnforcer ::LoadModel() {
  lock_guard<mutex> lock(policyMutex);
  Enforcer::LoadModel();
}

// ClearPolicy clears all policy.
void SyncedEnforcer ::ClearPolicy() {
  lock_guard<mutex> lock(policyMutex);
  Enforcer::ClearPolicy();
}

// LoadPolicy reloads the policy from file/database.
void SyncedEnforcer ::LoadPolicy() {
  lock_guard<mutex> lock(policyMutex);
  Enforcer::LoadPolicy();
}

// LoadFilteredPolicy reloads a filtered policy from file/database.
void SyncedEnforcer ::LoadFilteredPolicy(Filter f) {
  lock_guard<mutex> lock(policyMutex);
  Enforcer::LoadFilteredPolicy(f);
}

// LoadIncrementalFilteredPolicy reloads a filtered policy from file/database.
// void SyncedEnforcer ::LoadIncrementalFilteredPolicy(Filter f) {
//   lock_guard<mutex> lock(policyMutex);
//   Enforcer::LoadIncrementalFilteredPolicy(f);
// }

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
void SyncedEnforcer ::SavePolicy() {
  lock_guard<mutex> lock(policyMutex);
  Enforcer::SavePolicy();
}

// BuildRoleLinks manually rebuild the role inheritance relations.
void SyncedEnforcer ::BuildRoleLinks() {
  lock_guard<mutex> lock(policyMutex);
  Enforcer::BuildRoleLinks();
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
bool SyncedEnforcer ::Enforce(Scope s) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::Enforce(s);
}

// Enforce with a vector param,decides whether a "subject" can access a
// "object" with the operation "action", input parameters are usually: (sub,
// obj, act).
bool SyncedEnforcer ::Enforce(vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::Enforce(params);
}

// Enforce with a map param,decides whether a "subject" can access a "object"
// with the operation "action", input parameters are usually: (sub, obj, act).
bool SyncedEnforcer ::Enforce(unordered_map<string, string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::Enforce(params);
}

// // BatchEnforce enforce in batches
// vector<bool> SyncedEnforcer ::BatchEnforce(vector<vector<string>> requests) {
//   lock_guard<mutex> lock(policyMutex);
//   return Enforcer::BatchEnforce(requests);
// }

// // BatchEnforceWithMatcher enforce with matcher in batches
// vector<bool> SyncedEnforcer ::BatchEnforceWithMatcher(string matcher, vector<vector<string>> requests) {
//   lock_guard<mutex> lock(policyMutex);
//   return Enforcer::BatchEnforce(matcher, requests);
// }

// GetAllSubjects gets the list of subjects that show up in the current policy.
vector<string> SyncedEnforcer ::GetAllSubjects() {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetAllSubjects();
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
vector<string> SyncedEnforcer ::GetAllNamedSubjects(string ptype) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetAllNamedSubjects(ptype);
}

// GetAllObjects gets the list of objects that show up in the current policy.
vector<string> SyncedEnforcer ::GetAllObjects() {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetAllObjects();
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
vector<string> SyncedEnforcer ::GetAllNamedObjects(string ptype) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetAllNamedObjects(ptype);
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
vector<string> SyncedEnforcer ::GetAllNamedActions(string ptype) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetAllNamedActions(ptype);
}

// GetAllRoles gets the list of roles that show up in the current policy.
vector<string> SyncedEnforcer ::GetAllRoles() {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetAllRoles();
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
vector<string> SyncedEnforcer ::GetAllNamedRoles(string ptype) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetAllNamedRoles(ptype);
}

// GetPolicy gets all the authorization rules in the policy.
vector<vector<string>> SyncedEnforcer ::GetPolicy() {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetPolicy();
}

// GetNamedPolicy gets all the authorization rules in the named policy.
vector<vector<string>> SyncedEnforcer ::GetNamedPolicy(string ptype) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetNamedPolicy(ptype);
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
vector<vector<string>> SyncedEnforcer ::GetFilteredNamedPolicy(string ptype, int fieldIndex, vector<string> fieldValues) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetFilteredNamedPolicy(ptype, fieldIndex, fieldValues);
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
vector<vector<string>> SyncedEnforcer ::GetGroupingPolicy() {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetGroupingPolicy();
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
vector<vector<string>> SyncedEnforcer ::GetFilteredGroupingPolicy(int fieldIndex, vector<string> fieldValues) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetFilteredGroupingPolicy(fieldIndex, fieldValues);
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
vector<vector<string>> SyncedEnforcer ::GetNamedGroupingPolicy(string ptype) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetNamedGroupingPolicy(ptype);
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
vector<vector<string>> SyncedEnforcer ::GetFilteredNamedGroupingPolicy(string ptype, int fieldIndex, vector<string> fieldValues) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::GetFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues);
}

// HasPolicy determines whether an authorization rule exists.
bool SyncedEnforcer ::HasPolicy(vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::HasPolicy(params);
}

// HasNamedPolicy determines whether a named authorization rule exists.
bool SyncedEnforcer ::HasNamedPolicy(string ptype, vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::HasNamedPolicy(ptype, params);
}

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool SyncedEnforcer ::AddPolicy(vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::AddPolicy(params);
}

// AddPolicies adds authorization rules to the current policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding rule by adding the new rule.
bool SyncedEnforcer ::AddPolicies(vector<vector<string>> rules) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::AddPolicies(rules);
}

// AddNamedPolicy adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool SyncedEnforcer ::AddNamedPolicy(string ptype, vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::AddNamedPolicy(ptype, params);
}

// AddNamedPolicies adds authorization rules to the current named policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding by adding the new rule.
bool SyncedEnforcer ::AddNamedPolicies(string ptype, vector<vector<string>> rules) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::AddNamedPolicies(ptype, rules);
}

// RemovePolicy removes an authorization rule from the current policy.
bool SyncedEnforcer ::RemovePolicy(vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemovePolicy(params);
}

// UpdatePolicy updates an authorization rule from the current policy.
// bool SyncedEnforcer ::UpdatePolicy(vector<string> oldPolicy, vector<string> newPolicy) {
//   lock_guard<mutex> lock(policyMutex);
//   return Enforcer::UpdatePolicy(oldPolicy, newPolicy);
// }

// bool SyncedEnforcer ::UpdateNamedPolicy(string ptype, vector<string> p1, vector<string> p2) {
//   lock_guard<mutex> lock(policyMutex);
//   return Enforcer::UpdateNamedPolicy(ptype, p1, p2);
// }

// // UpdatePolicies updates authorization rules from the current policies.
// bool SyncedEnforcer ::UpdatePolicies(vector<vector<string>> oldPolices, vector<vector<string>> newPolicies) {
//   lock_guard<mutex> lock(policyMutex);
//   return Enforcer::UpdatePolicies(oldPolices, newPolicies);
// }

// bool SyncedEnforcer ::UpdateNamedPolicies(string ptype, vector<vector<string>> p1, vector<vector<string>> p2) {
//   lock_guard<mutex> lock(policyMutex);
//   return Enforcer::UpdateNamedPolicies(ptype, p1, p2);
// }

// RemovePolicies removes authorization rules from the current policy.
bool SyncedEnforcer ::RemovePolicies(vector<vector<string>> rules) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemovePolicies(rules);
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
bool SyncedEnforcer ::RemoveFilteredPolicy(int fieldIndex, vector<string> fieldValues) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemoveFilteredPolicy(fieldIndex, fieldValues);
}

// RemoveNamedPolicy removes an authorization rule from the current named policy.
bool SyncedEnforcer ::RemoveNamedPolicy(string ptype, vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemoveNamedPolicy(ptype, params);
}

// RemoveNamedPolicies removes authorization rules from the current named policy.
bool SyncedEnforcer ::RemoveNamedPolicies(string ptype, vector<vector<string>> rules) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemoveNamedPolicies(ptype, rules);
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
bool SyncedEnforcer ::RemoveFilteredNamedPolicy(string ptype, int fieldIndex, vector<string> fieldValues) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemoveFilteredNamedPolicy(ptype, fieldIndex, fieldValues);
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
bool SyncedEnforcer ::HasGroupingPolicy(vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::HasGroupingPolicy(params);
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
bool SyncedEnforcer ::HasNamedGroupingPolicy(string ptype, vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::HasNamedGroupingPolicy(ptype, params);
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool SyncedEnforcer ::AddGroupingPolicy(vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::AddGroupingPolicy(params);
}

// AddGroupingPolicies adds role inheritance rulea to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
bool SyncedEnforcer ::AddGroupingPolicies(vector<vector<string>> rules) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::AddGroupingPolicies(rules);
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool SyncedEnforcer ::AddNamedGroupingPolicy(string ptype, vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::AddNamedGroupingPolicy(ptype, params);
}

// AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
bool SyncedEnforcer ::AddNamedGroupingPolicies(string ptype, vector<vector<string>> rules) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::AddNamedGroupingPolicies(ptype, rules);
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
bool SyncedEnforcer ::RemoveGroupingPolicy(vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemoveGroupingPolicy(params);
}

// RemoveGroupingPolicies removes role inheritance rules from the current policy.
bool SyncedEnforcer ::RemoveGroupingPolicies(vector<vector<string>> rules) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemoveGroupingPolicies(rules);
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
bool SyncedEnforcer ::RemoveFilteredGroupingPolicy(int fieldIndex, vector<string> fieldValues) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemoveFilteredGroupingPolicy(fieldIndex, fieldValues);
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
bool SyncedEnforcer ::RemoveNamedGroupingPolicy(string ptype, vector<string> params) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemoveNamedGroupingPolicy(ptype, params);
}

// RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
bool SyncedEnforcer ::RemoveNamedGroupingPolicies(string ptype, vector<vector<string>> rules) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemoveNamedGroupingPolicies(ptype, rules);
}

// bool SyncedEnforcer ::UpdateGroupingPolicy(vector<string> oldRule, vector<string> newRule) {
//   lock_guard<mutex> lock(policyMutex);
//   return Enforcer::UpdateGroupingPolicy(oldRule, newRule);
// }

// bool SyncedEnforcer ::UpdateNamedGroupingPolicy(string ptype, vector<string> oldRule, vector<string> newRule) {
//   lock_guard<mutex> lock(policyMutex);
//   return Enforcer::UpdateNamedGroupingPolicy(ptype, oldRule, newRule);
// }

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
bool SyncedEnforcer ::RemoveFilteredNamedGroupingPolicy(string ptype, int fieldIndex, vector<string> fieldValues) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::RemoveFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues);
}

// AddFunction adds a customized function.
void SyncedEnforcer ::AddFunction(string name, Function function, Index nargs) {
  lock_guard<mutex> lock(policyMutex);
  return Enforcer::AddFunction(name, function, nargs);
}


#endif // ENFORCER_SYNCED_CPP
