#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include "../rbac/role_manager.h"

using namespace std;

class Assertion {
public:
	string key;
	string value;
	vector<string> tokens;
	vector<vector<string>> policy;
	RoleManager* rm;

	void buildRoleLinks(RoleManager*);
};