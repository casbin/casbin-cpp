#pragma once

#include <vector>
#include <map>
#include <string>
#include <functional>

using namespace std;

struct Role {
	string name;
	vector<string> roles;
};

class RoleManager {
	map<string, Role> allRoles;
	function<bool(string, string)> matchingFunc;
	bool hasPattern;
public:
	void addMatchingFunc(function<bool(string, string)>);
	bool hasRole(string);
	void clear();
	bool createRole(string);
	bool addLink(string, string, string);
	bool deleteLink(string, string, string);
	vector<string> getRoles(string, string);
};
