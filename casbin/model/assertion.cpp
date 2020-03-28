#include "assertion.h"
#include <iostream>

void Assertion::buildRoleLinks(RoleManager* rolem) {
	rm = rolem;
	int charCount = count(value.begin(), value.end(), '_');
	
	for (vector<string> rule : policy) {
		if (charCount < 2) {
			throw invalid_argument("the number of \"_\" in role definition should be at least 2");
		}
		if (rule.size() < charCount) {
			throw underflow_error("grouping policy elements do not meet role definition");
		}
		if (charCount == 2) {
			rm->addLink(rule[0], rule[1]);
		}
		else if (charCount == 3) {
			rm->addLink(rule[0], rule[1], rule[2]);
		}
		else if (charCount == 4) {
			rm->addLink(rule[0], rule[1], rule[2]);
		}
	}
}