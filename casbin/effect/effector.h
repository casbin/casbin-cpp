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

#ifndef CASBIN_CPP_EFFECT_EFFECTOR
#define CASBIN_CPP_EFFECT_EFFECTOR

#include <string>
#include <vector>

#include "effect.h"

using namespace std;

/**
 * Effector is the abstract class for Casbin effectors.
 */
class Effector{
    public:
        /**
         * MergeEffects merges all matching results collected by the enforcer into a single decision.
         *
         * @param expr the expression of [policy_effect].
         * @param effects the effects of all matched rules.
         * @param results the matcher results of all matched rules.
         * @return the final effect.
         */
        virtual bool MergeEffects(string expr, vector<Effect> effects, vector<float> results) = 0;
};

#endif