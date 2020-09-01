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

#include <algorithm>

#include "./assertion.h"
#include "../exception/illegal_argument_exception.h"

void Assertion :: BuildIncrementalRoleLinks(shared_ptr<RoleManager> rm, policy_op op, vector<vector<string>> rules) {
    this->rm = rm;
    int char_count = int(count(this->value.begin(), this->value.end(), '_'));

    if (char_count < 2)
        throw IllegalArgumentException("the number of \"_\" in role definition should be at least 2");

    for(int i = 0 ; i < rules.size() ; i++){
        vector<string> rule = rules[i];

        if (rule.size() < char_count)
            throw IllegalArgumentException("grouping policy elements do not meet role definition");
        if (rule.size() > char_count)
            rule = vector<string>(rule.begin(), rule.begin() + char_count);

        vector<string> domain(rule.begin() + 2, rule.end());

        switch(op) {
            case policy_op :: policy_add:
                this->rm->AddLink(rule[0], rule[1], domain);
                break;
            case policy_op :: policy_remove:
                this->rm->DeleteLink(rule[0], rule[1], domain);
        }
    }
}

void Assertion :: BuildRoleLinks(shared_ptr<RoleManager> rm) {
    this->rm = rm;
    int char_count = int(count(this->value.begin(), this->value.end(), '_'));

    if (char_count < 2)
        throw IllegalArgumentException("the number of \"_\" in role definition should be at least 2");

    for(int i = 0 ; i < this->policy.size() ; i++){
        vector<string> rule = policy[i];

        if (rule.size() < char_count)
            throw IllegalArgumentException("grouping policy elements do not meet role definition");
        if (rule.size() > char_count)
            rule = vector<string>(rule.begin(), rule.begin() + char_count);

        vector<string> domain(rule.begin() + 2, rule.end());
        this->rm->AddLink(rule[0], rule[1], domain);
    }

    // DefaultLogger df_logger;
    // df_logger.EnableLog(true);

    // Logger *logger = &df_logger;
    // LogUtil :: SetLogger(*logger);

    // LogUtil :: LogPrint("Role links for: " + Key);

    // this->rm->PrintRoles();
}