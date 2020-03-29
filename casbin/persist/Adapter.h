#ifndef CASBIN_CPP_PERSIST_ADAPTER
#define CASBIN_CPP_PERSIST_ADAPTER

#include <string>
#include <vector>

#include "../model/Model.h"
#include "../util/split.h"
#include "../util/trim.h"

using namespace std;

// LoadPolicyLine loads a text line as a policy rule to model.
void LoadPolicyLine(string line, Model model) {
	if(line == "" || line.find("#")==0) {
		return;
	}

	vector<string> tokens = split(line, ",", -1);
	for(int i = 0; i < tokens.size(); i++) {
		tokens[i] = trim(tokens[i]);
	}

	string key = tokens[0];
	string sec = key.substr(0,1);
    vector<string> newTokens(tokens.begin()+1, tokens.end());
    
    (model.M[sec].AMap[key]->Policy).push_back(newTokens);
}

/**
 * Adapter is the interface for Casbin adapters.
 */
class Adapter {
    public:

        /**
         * loadPolicy loads all policy rules from the storage.
         *
         * @param model the model.
         */
        virtual void loadPolicy(Model model) = 0;

        /**
         * savePolicy saves all policy rules to the storage.
         *
         * @param model the model.
         */
        virtual void savePolicy(Model model) = 0;

        /**
         * addPolicy adds a policy rule to the storage.
         * This is part of the Auto-Save feature.
         *
         * @param sec the section, "p" or "g".
         * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
         * @param rule the rule, like (sub, obj, act).
         */
        virtual void addPolicy(string sec, string ptype, vector<string> rule) = 0;

        /**
         * removePolicy removes a policy rule from the storage.
         * This is part of the Auto-Save feature.
         *
         * @param sec the section, "p" or "g".
         * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
         * @param rule the rule, like (sub, obj, act).
         */
        virtual void removePolicy(string sec, string ptype, vector<string> rule) = 0;

        /**
         * removeFilteredPolicy removes policy rules that match the filter from the storage.
         * This is part of the Auto-Save feature.
         *
         * @param sec the section, "p" or "g".
         * @param ptype the policy type, "p", "p2", .. or "g", "g2", ..
         * @param fieldIndex the policy rule's start index to be matched.
         * @param fieldValues the field values to be matched, value ""
         *                    means not to match this field.
         */
        void removeFilteredPolicy(string sec, string ptype, int fieldIndex, vector <string> fieldValues);
};

#endif