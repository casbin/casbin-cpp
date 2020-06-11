#ifndef CASBIN_CPP_EFFECT_DEFAULT_EFFECTOR
#define CASBIN_CPP_EFFECT_DEFAULT_EFFECTOR

#include "effector.h"

/**
 * DefaultEffector is default effector for Casbin.
 */
class DefaultEffector : public Effector{
    public:

        // NewDefaultEffector is the constructor for DefaultEffector.
        static DefaultEffector* NewDefaultEffector();

        /**
         * MergeEffects merges all matching results collected by the enforcer into a single decision.
         */
        bool MergeEffects(string expr, vector<Effect> effects, vector<float> results);
};

#endif