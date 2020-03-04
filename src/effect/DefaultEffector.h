// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string>

#include "Effect.h"
#include "Effector.h"
#include "exception/CasbinEffectExceptions.h"

/**
 * DefaultEffector is default effector for Casbin.
 */
class DefaultEffector : public Effector{
    public:
        /**
         * mergeEffects merges all matching results collected by the enforcer into a single decision.
         */
        bool mergeEffects(std::string expr, Effect effects[], float results[]) {
            bool result;

            unsigned int number_of_effects = sizeof(effects)/sizeof(effects[0]);

            if (!expr.compare("some(where (p_eft == allow))")) {
                result = false;
                for(unsigned int index = 0 ; index < number_of_effects ; index++){
                    if (effects[index] == Allow) {
                        result = true;
                        break;
                    }
                }
            } else if (!expr.compare("!some(where (p_eft == deny))")) {
                result = true;
                for(unsigned int index = 0 ; index < number_of_effects ; index++){
                    if (effects[index] == Deny) {
                        result = false;
                        break;
                    }
                }
            } else if (!expr.compare("some(where (p_eft == allow)) && !some(where (p_eft == deny))")) {
                result = false;
                for(unsigned int index = 0 ; index < number_of_effects ; index++){
                    if (effects[index] == Allow) {
                        result = true;
                    } else if (effects[index] == Deny) {
                        result = false;
                        break;
                    }
                }
            } else if (!expr.compare("priority(p_eft) || deny")) {
                result = false;
                for(unsigned int index = 0 ; index < number_of_effects ; index++){
                    if (effects[index] != Indeterminate) {
                        if (effects[index] == Allow) {
                            result = true;
                        } else {
                            result = false;
                        }
                        break;
                    }
                }
            } else {
                throw new UnsupportedOperationException("unsupported effect");
            }

            return result;
        }
};