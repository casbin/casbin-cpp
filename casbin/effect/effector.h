#pragma once

#ifdef CASBIN_EXPORTS
#define EFFECTOR_API __declspec(dllexport)
#else
#define EFFECTOR_API __declspec(dllimport)
#endif

#include <string>
#include <vector>

using namespace std;

enum class effect { allow, indeterminate, deny };

class EFFECTOR_API effector {
public:
	static auto merge_effects(const string&, const vector<effect>&) -> bool;
};