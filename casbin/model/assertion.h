#pragma once

#include <string>
#include <vector>
#include <deque>
#include <stdexcept>
#include "../rbac/role_manager.h"

using namespace std;

class assertion {
public:
	string key;
	string value;
	vector<string> tokens;
	deque<vector<string>> policy;
	role_manager* rm;

	void build_role_links(role_manager*);
};