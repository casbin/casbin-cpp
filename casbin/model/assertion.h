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

#ifndef CASBIN_CPP_MODEL_ASSERTION
#define CASBIN_CPP_MODEL_ASSERTION

#include <memory>

#include "../rbac/role_manager.h"

enum policy_op{
    policy_add,
    policy_remove
};
typedef enum policy_op policy_op;

// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act
class Assertion {
    public:

        string key;
        string value;
        vector<string> tokens;
        vector<vector<string>> policy;
        shared_ptr<RoleManager> rm;

        void BuildIncrementalRoleLinks(shared_ptr<RoleManager> rm, policy_op op, vector<vector<string>> rules);

        void BuildRoleLinks(shared_ptr<RoleManager> rm);
};

#endif