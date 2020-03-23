#pragma once

#ifdef CASBIN_EXPORTS
#define EFFECTOR_API __declspec(dllexport)
#else
#define EFFECTOR_API __declspec(dllimport)
#endif

#include <string>
#include <vector>

using namespace std;

enum class Effect { Allow, Indeterminate, Deny };

class EFFECTOR_API Effector {
public:
	bool mergeEffects(string, vector<Effect>);
};