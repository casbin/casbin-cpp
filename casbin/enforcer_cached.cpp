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

#include "./enforcer_cached.h"
#include "./persist/watcher_ex.h"
#include "./persist/file_adapter/file_adapter.h"
#include "./rbac/default_role_manager.h"
#include "./effect/default_effector.h"
#include "./exception/casbin_adapter_exception.h"
#include "./exception/casbin_enforcer_exception.h"
#include "./util/util.h"
using namespace std;


/**
 * Enforcer is the default constructor.
 */
CachedEnforcer ::CachedEnforcer() {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a model file and a policy file.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 */
CachedEnforcer ::CachedEnforcer(string model_path, string policy_file): Enforcer(model_path, policy_file) {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a database adapter.
 *
 * @param model_path the path of the model file.
 * @param adapter the adapter.
 */
CachedEnforcer ::CachedEnforcer(string model_path, shared_ptr<Adapter> adapter): Enforcer(model_path,adapter) {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a model and a database adapter.
 *
 * @param m the model.
 * @param adapter the adapter.
 */
CachedEnforcer :: CachedEnforcer(shared_ptr<Model> m, shared_ptr<Adapter> adapter): Enforcer(m,adapter) {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a model.
 *
 * @param m the model.
 */
CachedEnforcer ::CachedEnforcer(shared_ptr<Model> m): Enforcer(m) {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a model file.
 *
 * @param model_path the path of the model file.
 */
CachedEnforcer ::CachedEnforcer(string model_path): Enforcer(model_path) {
    this->enableCache = true;
}

/**
 * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
 *
 * @param model_path the path of the model file.
 * @param policyFile the path of the policy file.
 * @param enableLog whether to enable Casbin's log.
 */
CachedEnforcer :: CachedEnforcer(string model_path, string policy_file, bool enable_log): Enforcer(model_path,policy_file,enable_log) {
   this->enableCache = true;
}

CachedEnforcer::CachedEnforcer(const CachedEnforcer& ce):Enforcer(ce){
   this->m = ce.m;
   this->enableCache = ce.enableCache;
}

CachedEnforcer::CachedEnforcer(CachedEnforcer&& ce):Enforcer(ce){
   this->m = move(ce.m);
   this->enableCache = ce.enableCache;
}


void CachedEnforcer::EnableCache(const bool& enableCache) {
  this->enableCache = enableCache;
}

pair<bool, bool> CachedEnforcer::getCachedResult(const string& key) {
  locker.lock();
  bool ok = m.count(key);
  if (!ok) {
    locker.unlock();
    return pair<bool, bool>(false, false);
  }

  pair<bool, bool> res_ok(m[key], ok);
  locker.unlock();
  return res_ok;
}

void CachedEnforcer::setCachedResult(const string& key, const bool& res) {
  locker.lock();
  m[key] = res;
  locker.unlock();
}

void CachedEnforcer::InvalidateCache() {
   m.clear(); 
}

// Enforce decides whether a "subject" can access a "object" with the operation
// "action", input parameters are usually: (sub, obj, act).
bool CachedEnforcer ::Enforce(Scope scope) {
  return EnforceWithMatcher("", scope);
}

// Enforce with a vector param,decides whether a "subject" can access a "object"
// with the operation "action", input parameters are usually: (sub, obj, act).
bool CachedEnforcer::Enforce(vector<string> params) {
  return EnforceWithMatcher("", params);
}

// Enforce with a map param,decides whether a "subject" can access a "object"
// with the operation "action", input parameters are usually: (sub, obj, act).
bool CachedEnforcer::Enforce(unordered_map<string, string> params) {
  return EnforceWithMatcher("", params);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can
// access a "object" with the operation "action", input parameters are usually:
// (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool CachedEnforcer ::EnforceWithMatcher(string matcher, Scope scope) {
  return Enforcer::EnforceWithMatcher(matcher, scope);
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can
// access a "object" with the operation "action", input parameters are usually:
// (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool CachedEnforcer::EnforceWithMatcher(string matcher, vector<string> params) {
  if (!enableCache) {
    return Enforcer::EnforceWithMatcher(matcher,params);
  }

  string key;
  for (auto r : params) {
    key += r;
    key += "$$";
  }
  key += matcher;
  key += "$";

  pair<bool, bool> res_ok = getCachedResult(key);

  if (res_ok.second) {
    return res_ok.first;
  }

  bool res = Enforcer::EnforceWithMatcher(matcher,params);
  setCachedResult(key, res);
  return res;
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can
// access a "object" with the operation "action", input parameters are usually:
// (matcher, sub, obj, act), use model matcher by default when matcher is "".
bool CachedEnforcer::EnforceWithMatcher(string matcher, unordered_map<string, string> params) {
  if (!enableCache) {
    return Enforcer::EnforceWithMatcher(matcher,params);
  }

  string key;
  for (auto r : params) {
    key += r.second;
    key += "$$";
  }
  key += matcher;
  key += "$";

  pair<bool, bool> res_ok = getCachedResult(key);

  if (res_ok.second) {
    return res_ok.first;
  }

  bool res = Enforcer::EnforceWithMatcher(matcher,params);
  setCachedResult(key, res);
  return res;
}