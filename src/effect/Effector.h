#include <string>

#include "Effect.h"


class Effector{
    public:
        virtual bool mergeEffects(std::string expr, Effect effects[], float results[]) = 0;
};