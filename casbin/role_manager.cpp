#include "pch.h"
#include "role_manager.h"

Role newRole(string name) {
	Role temp;
	temp.name = name;

	return temp;
}

Role deleteRole(Role role1, string name) {
	for (auto itr = role1.roles.begin(); itr != role1.roles.end();itr++) {
		if (*itr == name) role1.roles.erase(itr);
	}

	return role1;
}

void RoleManager::addMatchingFunc(function<bool(string, string)> fn) {
	matchingFunc = fn;
	hasPattern = true;
}

bool RoleManager::hasRole(string name) {
	if (hasPattern) {
		for (auto itr = allRoles.begin(); itr != allRoles.end(); itr++) {
			if (matchingFunc(name, itr->first)) {
				return true;
			}
		}
	}
	else {
		auto itr = allRoles.find(name);
		return itr != allRoles.end() ? true : false;
	}

	return false;
}

void RoleManager::clear() {
	allRoles.clear();
}

bool RoleManager::createRole(string name) {
	if (allRoles.find(name) == allRoles.end()) {
		allRoles.insert({ name, newRole(name) });
	}

	if (hasPattern) {
		for (auto itr = allRoles.begin(); itr != allRoles.end(); itr++) {
			if (matchingFunc(name, itr->first) && name != itr->first) {
				allRoles.find(name)->second.roles.push_back(itr->first);
			}
		}
	}

	return true;
}

bool RoleManager::addLink(string name1, string name2, string domain) {
	name1.insert(0, domain + "::");
	name2.insert(0, domain + "::");
	createRole(name1);
	createRole(name2);
	allRoles.find(name1)->second.roles.push_back(name2);

	return true;
}

bool RoleManager::deleteLink(string name1, string name2, string domain) {
	name1.insert(0, domain + "::");
	name2.insert(0, domain + "::");
	if (allRoles.find(name1) != allRoles.end()) {
		allRoles.find(name1)->second = deleteRole(allRoles.find(name1)->second, name2);
		return true;
	}
	else return false;
}

vector<string> RoleManager::getRoles(string name, string domain) {
	name = domain + "::" + name;
	
	if (!hasRole(name)) return vector<string>();

	vector<string> temp = allRoles.find(name)->second.roles;

	for (vector<string>::iterator itr = temp.begin(); itr != temp.end(); itr++) {
		string tempstr = *itr;
		*itr = tempstr.substr(domain.length() + 2);
	}

	return temp;
}

