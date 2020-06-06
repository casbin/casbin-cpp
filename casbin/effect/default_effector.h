#ifndef CASBIN_CPP_EFFECT_DEFAULT_EFFECTOR
#define CASBIN_CPP_EFFECT_DEFAULT_EFFECTOR

#include <vector>

#include "effector.h"
#include "../exception/UnsupportedOperationException.h"

/**
 * DefaultEffector is default effector for Casbin.
 */
class DefaultEffector : public Effector{
    public:

        // NewDefaultEffector is the constructor for DefaultEffector.
        static DefaultEffector* NewDefaultEffector(){
            DefaultEffector* e = new DefaultEffector;
            return e;
        }

        /**
         * MergeEffects merges all matching results collected by the enforcer into a single decision.
         */
        bool MergeEffects(string expr, vector<Effect> effects, vector<float> results) {
            bool result;

            unsigned int number_of_effects = sizeof(effects) / sizeof(effects[0]);

            if (!expr.compare("some(where (p_eft == allow))")) {
                result = false;
                for(unsigned int index = 0 ; index < number_of_effects ; index++){
                    if (effects[index] == Effect::Allow) {
                        result = true;
                        break;
                    }
                }
            } else if (!expr.compare("!some(where (p_eft == deny))")) {
                result = true;
                for(unsigned int index = 0 ; index < number_of_effects ; index++){
                    if (effects[index] == Effect::Deny) {
                        result = false;
                        break;
                    }
                }
            } else if (!expr.compare("some(where (p_eft == allow)) && !some(where (p_eft == deny))")) {
                result = false;
                for(unsigned int index = 0 ; index < number_of_effects ; index++){
                    if (effects[index] == Effect::Allow) {
                        result = true;
                    } else if (effects[index] == Effect::Deny) {
                        result = false;
                        break;
                    }
                }
            } else if (!expr.compare("priority(p_eft) || deny")) {
                result = false;
                for(unsigned int index = 0 ; index < number_of_effects ; index++){
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
                throw new UnsupportedOperationException("unsupported effect");
            }

            return result;
        }
};

#endif