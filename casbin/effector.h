#pragma once

#include <string>
#include <vector>

using namespace std;

enum class Effect { Allow, Indeterminate, Deny };

bool mergeEffects(string, vector<Effect>);