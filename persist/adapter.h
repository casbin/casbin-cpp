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

# include "model/model.h"

// LoadPolicyLine loads a text line as a policy rule to model.
int loadPolicyLine(string line, Model model) {
	if((line == "")||(line[0]=='#')) {
	    return 0;
	}

   string word = ""; 
   string tokens[10];
   int i =0;
   for (auto x : line) 
   { 
       if (x == ' ') 
       {   
           tokens[i++] = word;
           word = ""; 
       } 
       else
       { 
           word = word + x; 
       } 
   }
	string key = tokens[0];
	string sec;
    sec[0] = key[0];
    sec[1] = key[1];
	// model[sec][key].Policy = append(model[sec][key].Policy, tokens[1:])
}
// Adapter is the class for Casbin adapters.
class Adapter {
	// LoadPolicy loads all policy rules from the storage.
	string loadPolicy(Model model);
	// SavePolicy saves all policy rules to the storage.
	string savePolicy(Model model);

	// AddPolicy adds a policy rule to the storage.
	// This is part of the Auto-Save feature.
	string addPolicy(string sec, string ptype, string rule[]);
	// RemovePolicy removes a policy rule from the storage.
	// This is part of the Auto-Save feature.
	string removePolicy(string sec, string ptype, string rule[]);
};
