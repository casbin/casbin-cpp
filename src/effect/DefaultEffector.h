#include <string>

#include "Effect.h"
#include "Effector.h"
#include "exception/CasbinEffectExceptions.h"

class DefaultEffector : public Effector{
    public:
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