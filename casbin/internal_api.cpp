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

#include "./enforcer.h"
#include "./persist/batch_adapter.h"
#include "./util/util.h"
#include "./persist/watcher_ex.h"
#include "./exception/unsupported_operation_exception.h"

// addPolicy adds a rule to the current policy.
bool Enforcer :: addPolicy(string sec, string p_type, vector<string> rule) {
    bool rule_added = this->model->AddPolicy(sec, p_type, rule);
    if(!rule_added)
        return rule_added;

    if (sec == "g") {
        vector<vector<string>> rules{rule};
        this->BuildIncrementalRoleLinks(policy_add, p_type, rules);
    }

    if (this->adapter && this->auto_save) {
        try {
            this->adapter->AddPolicy(sec, p_type, rule);
        }
        catch(UnsupportedOperationException e) {
        }
    }

    if (this->watcher && this->auto_notify_watcher) {
        if (IsInstanceOf<WatcherEx>(this->watcher.get())) {
            void* watcher = this->watcher.get();
            ((WatcherEx*)watcher)->UpdateForAddPolicy(rule);
        }
        else
            this->watcher->Update();
    }

    return rule_added;
}

// addPolicies adds rules to the current policy.
bool Enforcer :: addPolicies(string sec, string p_type, vector<vector<string>> rules) {
    bool rules_added = this->model->AddPolicies(sec, p_type, rules);
    if (!rules_added)
        return rules_added;

    if (sec == "g")
        this->BuildIncrementalRoleLinks(policy_add, p_type, rules);


    if (this->adapter && this->auto_save) {
        try {
            dynamic_cast<BatchAdapter*>(this->adapter.get())->AddPolicies(sec, p_type, rules);
        }
        catch(UnsupportedOperationException e) {
        }
    }

    if (this->watcher && this->auto_notify_watcher)
        this->watcher->Update();

    return rules_added;
}

// removePolicy removes a rule from the current policy.
bool Enforcer :: removePolicy(string sec, string p_type, vector<string> rule) {
    bool rule_removed = this->model->RemovePolicy(sec, p_type, rule);
    if(!rule_removed)
        return rule_removed;

    if (sec == "g") {
        vector<vector<string>> rules{rule};
        this->BuildIncrementalRoleLinks(policy_add, p_type, rules);
    }
    
    if (this->adapter && this->auto_save) {
        try {
            this->adapter->RemovePolicy(sec, p_type, rule);
        }
        catch (UnsupportedOperationException e) {
        }
    }

    if(this->watcher && this->auto_notify_watcher){
        if (IsInstanceOf<WatcherEx>(this->watcher.get())) {
            void* watcher = this->watcher.get();
            ((WatcherEx*)watcher)->UpdateForRemovePolicy(rule);
        }
        else
            this->watcher->Update();
    }

    return rule_removed;
}

// removePolicies removes rules from the current policy.
bool Enforcer :: removePolicies(string sec, string p_type, vector<vector<string>> rules) {
    bool rules_removed = this->model->AddPolicies(sec, p_type, rules);
    if (!rules_removed)
        return rules_removed;

    if (sec == "g")
        this->BuildIncrementalRoleLinks(policy_add, p_type, rules);

    if (this->adapter && this->auto_save) {
        try{
            dynamic_cast<BatchAdapter*>(this->adapter.get())->RemovePolicies(sec, p_type, rules);
        }
        catch(UnsupportedOperationException e){
        }
    }

    if (this->watcher && this->auto_notify_watcher)
        this->watcher->Update();

    return rules_removed;
}

// removeFilteredPolicy removes rules based on field filters from the current policy.
bool Enforcer :: removeFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values){
    pair<int, vector<vector<string>>> p = this->model->RemoveFilteredPolicy(sec, p_type, field_index, field_values);
    bool rule_removed = p.first;
    vector<vector<string>> effects = p.second;

    if(!rule_removed)
        return rule_removed;

    if (sec == "g")
        this->BuildIncrementalRoleLinks(policy_remove, p_type, effects);

    if (this->adapter && this->auto_save) {
        try {
            this->adapter->RemoveFilteredPolicy(sec, p_type, field_index, field_values); \
        }
        catch (UnsupportedOperationException e) {
        }
    }

    if (this->watcher && this->auto_notify_watcher) {
        if (IsInstanceOf<WatcherEx>(this->watcher.get())) {
            void* watcher = this->watcher.get();
            ((WatcherEx*)watcher)->UpdateForRemoveFilteredPolicy(field_index, field_values);
        }
        else
            this->watcher->Update();
    }

    return rule_removed;
}