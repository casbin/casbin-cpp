#include "assertion.h"
#include <iostream>

auto assertion::build_role_links(role_manager* rolem) -> void
{
	rm = rolem;
	const int char_count = count(value.begin(), value.end(), '_');
	
	for (auto rule : policy) {
		if (char_count < 2) {
			throw invalid_argument("the number of \"_\" in role definition should be at least 2");
		}
		if (rule.size() < char_count) {
			throw underflow_error("grouping policy elements do not meet role definition");
		}
		if (char_count == 2) {
			rm->add_link(rule[0], rule[1]);
		}
		else if (char_count == 3) {
			rm->add_link(rule[0], rule[1], rule[2]);
		}
		else if (char_count == 4) {
			rm->add_link(rule[0], rule[1], rule[2]);
		}
	}
}
