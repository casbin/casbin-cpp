#pragma once

#include "pch.h"

#include "./adapter.h"
#include "../util/util.h"

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