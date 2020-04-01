#include "effector.h"

auto effector::merge_effects(const string& expr, const vector<effect>& effects) -> bool
{
	auto result = false;
	if (expr == "some(where (p_eft == allow))") {
		result = false;
		for (auto eft : effects) {
			if (eft == effect::allow) {
				result = true;
				break;
			}
		}
	}
	else if (expr == "!some(where (p_eft == deny))") {
		result = true;
		for (auto eft : effects) {
			if (eft == effect::deny) {
				result = false;
				break;
			}
		}
	}
	else if (expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))") {
		result = false;
		for (auto eft : effects) {
			if (eft == effect::allow) {
				result = true;
			}
			else if (eft == effect::deny) {
				result = false;
				break;
			}
		}
	}
	else if (expr == "priority(p_eft) || deny") {
		result = false;
		for (auto eft : effects) {
			if (eft != effect::indeterminate) {
				if (eft == effect::allow) {
					result = true;
				}
				else {
					result = false;
				}
				break;
			}
		}
	}

	return result;
}
