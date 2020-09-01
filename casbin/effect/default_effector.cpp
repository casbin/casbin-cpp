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

#include "./default_effector.h"
#include "../exception/unsupported_operation_exception.h"

/**
 * MergeEffects merges all matching results collected by the enforcer into a single decision.
 */
bool DefaultEffector :: MergeEffects(string expr, vector<Effect> effects, vector<float> results) {
    bool result;

    if (!expr.compare("some(where (p.eft == allow))")) {
        result = false;
        for(unsigned int index = 0 ; index < effects.size() ; index++){
            if (effects[index] == Effect::Allow) {
                result = true;
                break;
            }
        }
    } else if (!expr.compare("!some(where (p.eft == deny))")) {
        result = true;
        for(unsigned int index = 0 ; index < effects.size(); index++){
            if (effects[index] == Effect::Deny) {
                result = false;
                break;
            }
        }
    } else if (!expr.compare("some(where (p.eft == allow)) && !some(where (p.eft == deny))")) {
        result = false;
        for(unsigned int index = 0 ; index < effects.size(); index++){
            if (effects[index] == Effect::Allow) {
                result = true;
            } else if (effects[index] == Effect::Deny) {
                result = false;
                break;
            }
        }
    } else if (!expr.compare("priority(p.eft) || deny")) {
        result = false;
        for(unsigned int index = 0 ; index < effects.size(); index++){
            if (effects[index] != Effect::Indeterminate) {
                if (effects[index] == Effect::Allow) {
                    result = true;
                } else {
                    result = false;
                }
                break;
            }
        }
    } else {
        throw UnsupportedOperationException("unsupported effect");
    }

    return result;
}