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

#ifndef CASBIN_CPP_PERSIST_ADAPTER
#define CASBIN_CPP_PERSIST_ADAPTER

#include <string>
#include <vector>

#include "../model/model.h"

using namespace std;

// LoadPolicyLine loads a text line as a policy rule to model.
void LoadPolicyLine(string line, Model* model);

/**
 * Adapter is the interface for Casbin adapters.
 */
class Adapter {
    public:

        string  file_path;
        bool filtered;


        /**
         * LoadPolicy loads all policy rules from the storage.
         *
         * @param model the model.
         */
        virtual void LoadPolicy(Model* model) = 0;


        /**
         * SavePolicy saves all policy rules to the storage.
         *
         * @param model the model.
         */
        virtual void SavePolicy(Model* model) = 0;

        /**
         * AddPolicy adds a policy rule to the storage.
         * This is part of the Auto-Save feature.
         *
         * @param sec the section, "p" or "g".
         * @param p_type the policy type, "p", "p2", .. or "g", "g2", ..
         * @param rule the rule, like (sub, obj, act).
         */
        virtual void AddPolicy(string& sec, string& p_type, vector<string>& rule) = 0;

        /**
         * RemovePolicy removes a policy rule from the storage.
         * This is part of the Auto-Save feature.
         *
         * @param sec the section, "p" or "g".
         * @param p_type the policy type, "p", "p2", .. or "g", "g2", ..
         * @param rule the rule, like (sub, obj, act).
         */
        virtual void RemovePolicy(string& sec, string& p_type, vector<string>& rule) = 0;

        /**
         * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
         * This is part of the Auto-Save feature.
         *
         * @param sec the section, "p" or "g".
         * @param p_type the policy type, "p", "p2", .. or "g", "g2", ..
         * @param field_index the policy rule's start index to be matched.
         * @param field_values the field values to be matched, value ""
         *                    means not to match this field.
         */
        virtual void RemoveFilteredPolicy(string& sec, string& ptype, int field_index, vector<string>& field_values) = 0;

        virtual bool IsFiltered() = 0;
};

#endif