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

#ifndef CASBIN_CPP_ENFORCER_CACHED
#define CASBIN_CPP_ENFORCER_CACHED

#include <mutex>

#include "./enforcer.h"

class CachedEnforcer : public Enforcer {
public:
    unordered_map<string, bool> m;
    bool enableCache;
    mutex locker;

    CachedEnforcer(const CachedEnforcer& ce);
    CachedEnforcer(CachedEnforcer&& ce);

    void EnableCache(const bool& enableCache);
    pair<bool, bool> getCachedResult(const string& key);
    void setCachedResult(const string& key, const bool& res);
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
    CachedEnforcer(string model_path, string policy_file);
    /**
         * Enforcer initializes an enforcer with a database adapter.
         *
         * @param model_path the path of the model file.
         * @param adapter the adapter.
         */
    CachedEnforcer(string model_path, shared_ptr<Adapter> adapter);
    /**
         * Enforcer initializes an enforcer with a model and a database adapter.
         *
         * @param m the model.
         * @param adapter the adapter.
         */
    CachedEnforcer(shared_ptr<Model> m, shared_ptr<Adapter> adapter);
    /**
         * Enforcer initializes an enforcer with a model.
         *
         * @param m the model.
         */
    CachedEnforcer(shared_ptr<Model> m);
    /**
         * Enforcer initializes an enforcer with a model file.
         *
         * @param model_path the path of the model file.
         */
    CachedEnforcer(string model_path);
    /**
         * Enforcer initializes an enforcer with a model file, a policy file and an enable log flag.
         *
         * @param model_path the path of the model file.
         * @param policy_file the path of the policy file.
         * @param enable_log whether to enable Casbin's log.
         */
    CachedEnforcer(string model_path, string policy_file, bool enable_log);

    bool Enforce(Scope scope);
    // Enforce with a vector param,decides whether a "subject" can access a
    // "object" with the operation "action", input parameters are usually: (sub,
    // obj, act).
    bool Enforce(vector<string> params);
    // Enforce with a map param,decides whether a "subject" can access a "object"
    // with the operation "action", input parameters are usually: (sub, obj, act).
    bool Enforce(unordered_map<string, string> params);
    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
    // access a "object" with the operation "action", input parameters are
    // usually: (matcher, sub, obj, act), use model matcher by default when
    // matcher is "".
    bool EnforceWithMatcher(string matcher, Scope scope);
    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
    // access a "object" with the operation "action", input parameters are
    // usually: (matcher, sub, obj, act), use model matcher by default when
    // matcher is "".
    bool EnforceWithMatcher(string matcher, vector<string> params);
    // EnforceWithMatcher use a custom matcher to decides whether a "subject" can
    // access a "object" with the operation "action", input parameters are
    // usually: (matcher, sub, obj, act), use model matcher by default when
    // matcher is "".
    bool EnforceWithMatcher(string matcher, unordered_map<string, string> params);
};
#endif