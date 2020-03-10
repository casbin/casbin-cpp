#ifndef CASBIN_CPP_EFFECT_EFFECTOR
#define CASBIN_CPP_EFFECT_EFFECTOR

#include <string>

#include "Effect.h"

#endif

using namespace std;

/**
 * Effector is the abstract class for Casbin effectors.
 */
class Effector{
    public:
        /**
         * mergeEffects merges all matching results collected by the enforcer into a single decision.
         *
         * @param expr the expression of [policy_effect].
         * @param effects the effects of all matched rules.
         * @param results the matcher results of all matched rules.
         * @return the final effect.
         */
        virtual bool mergeEffects(string expr, Effect effects[], float results[]) = 0;
};