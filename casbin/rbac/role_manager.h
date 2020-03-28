#pragma once

#ifdef CASBIN_EXPORTS
#define ROLEMANAGER_API __declspec(dllexport)
#else
#define ROLEMANAGER_API __declspec(dllimport)
#endif

#include <vector>
#include <map>
#include <string>
#include <functional>

using namespace std;

struct Role {
	string name;
	vector<Role*> roles;
	void addRole(Role*);
	void deleteRole(Role*);
	bool hasRole(string, int hierarchyLevel);
	vector<string> getRoles();
};

class ROLEMANAGER_API RoleManager {
	map<string, Role*> allRoles;
	function<bool(string, string)> matchingFunc;
	bool hasPattern = false;
	int maxHierarchyLevel = 10;
public:
	void addMatchingFunc(function<bool(string, string)>);
	bool hasRole(string);
	void clear();
	Role* createRole(string);
	void addLink(string, string, string);
	void addLink(string, string);
	void deleteLink(string, string, string);
	void deleteLink(string, string);
	bool hasLink(string, string, string);
	bool hasLink(string, string);
	vector<string> getRoles(string, string);
	vector<string> getRoles(string);
};
