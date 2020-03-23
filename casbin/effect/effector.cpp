#include "effector.h"

bool Effector::mergeEffects(string expr, vector<Effect> effects) {
	bool result = false;
	if (expr == "some(where (p_eft == allow))") {
		result = false;
		for (Effect eft : effects) {
			if (eft == Effect::Allow) {
				result = true;
				break;
			}
		}
	}
	else if (expr == "!some(where (p_eft == deny))") {
		result = true;
		for (Effect eft : effects) {
			if (eft == Effect::Deny) {
				result = false;
				break;
			}
		}
	}
	else if (expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))") {
		result = false;
		for (Effect eft : effects) {
			if (eft == Effect::Allow) {
				result = true;
			}
			else if (eft == Effect::Deny) {
				result = false;
				break;
			}
		}
	}
	else if (expr == "priority(p_eft) || deny") {
		result = false;
		for (Effect eft : effects) {
			if (eft != Effect::Indeterminate) {
				if (eft == Effect::Allow) {
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