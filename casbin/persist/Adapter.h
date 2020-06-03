#ifndef CASBIN_CPP_PERSIST_ADAPTER
#define CASBIN_CPP_PERSIST_ADAPTER

#include <string>
#include <vector>

#include "../model/model.h"
#include "../util/split.h"
#include "../util/trim.h"

using namespace std;

// LoadPolicyLine loads a text line as a policy rule to model.
void LoadPolicyLine(string line, Model* model) {
    if(line == "" || line.find("#")==0) {
        return;
    }

    vector<string> tokens = Split(line, ",", -1);
    for (int i = 0; i < tokens.size(); i++) {
        tokens[i] = Trim(tokens[i]);
    }

    string key = tokens[0];
    string sec = key.substr(0,1);
    vector<string> new_tokens(tokens.begin()+1, tokens.end());
    
    (model->m[sec].assertion_map[key]->policy).push_back(new_tokens);
}

/**
 * Adapter is the interface for Casbin adapters.
 */
class Adapter {
    public:

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
        virtual void AddPolicy(string sec, string p_type, vector<string> rule) = 0;

        /**
         * RemovePolicy removes a policy rule from the storage.
         * This is part of the Auto-Save feature.
         *
         * @param sec the section, "p" or "g".
         * @param p_type the policy type, "p", "p2", .. or "g", "g2", ..
         * @param rule the rule, like (sub, obj, act).
         */
        virtual void RemovePolicy(string sec, string p_type, vector<string> rule) = 0;

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
        virtual void RemoveFilteredPolicy(string sec, string ptype, int field_index, vector<string> field_values) = 0;

        virtual bool IsFiltered() = 0;
};

#endif