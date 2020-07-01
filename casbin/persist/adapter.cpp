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

#include "./adapter.h"
#include "../util/util.h"

// LoadPolicyLine loads a text line as a policy rule to model.
void LoadPolicyLine(string line, Model* model) {
    if(line == "" || line.find("#")==0)
        return;

    vector<string> tokens = Split(line, ",", -1);
    for (int i = 0; i < tokens.size(); i++)
        tokens[i] = Trim(tokens[i]);

    string key = tokens[0];
    string sec = key.substr(0,1);
    vector<string> new_tokens(tokens.begin()+1, tokens.end());

    if (model->m.find(sec) == model->m.end())
        model->m[sec] = AssertionMap();

    (model->m[sec].assertion_map[key]->policy).push_back(new_tokens);
}