#include "role_manager.h"

Role* newRole(string name) {
	Role* temp = new Role();
	temp->name = name;

	return temp;
}

void Role::addRole(Role* role) {
	for (Role* temp : roles) {
		if (temp->name == role->name) return;
	}
	roles.push_back(role);
}

void Role::deleteRole(Role* role) {
	for (auto itr = roles.begin(); itr != roles.end(); itr++) {
		Role* temp = *itr;
		if (temp->name == role->name) {
			roles.erase(itr);
			return;
		}
	}
}

bool Role::hasRole(string n, int hierarchyLevel) {
	if (name == name) return true;

	if (hierarchyLevel <= 0) return false;

	for (auto itr = roles.begin(); itr != roles.end(); itr++) {
		Role* temp = *itr;
		if (temp->hasRole(name, hierarchyLevel - 1)) return true;
	}

	return false;
}

vector<string> Role::getRoles() {
	vector<string> names;
	for (Role* temp : roles) {
		names.push_back(temp->name);
	}

	return names;
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

Role* RoleManager::createRole(string name) {
	Role* role;
	if (allRoles.find(name) == allRoles.end()) {
		role = newRole(name);
		allRoles.insert(make_pair(name, role));
	}
	else {
		role = allRoles.find(name)->second;
	}

	if (hasPattern) {
		for (auto itr = allRoles.begin(); itr != allRoles.end(); itr++) {
			if (matchingFunc(name, itr->first) && name != itr->first) {
				Role* role1 = itr->second;
				role->addRole(role1);
			}
		}
	}

	return role;
}

void RoleManager::clear() {
	allRoles.clear();
}

void RoleManager::addLink(string name1, string name2, string domain) {
	name1.insert(0, domain + "::");
	name2.insert(0, domain + "::");

	Role* role1 = createRole(name1);
	Role* role2 = createRole(name2);
	role1->addRole(role2);
}

void RoleManager::addLink(string name1, string name2) {
	Role* role1 = createRole(name1);
	Role* role2 = createRole(name2);
	role1->addRole(role2);
}

void RoleManager::deleteLink(string name1, string name2, string domain) {
	name1.insert(0, domain + "::");
	name2.insert(0, domain + "::");
	
	Role* role1 = createRole(name1);
	Role* role2 = createRole(name2);
	role1->deleteRole(role2);
}

void RoleManager::deleteLink(string name1, string name2) {
	Role* role1 = createRole(name1);
	Role* role2 = createRole(name2);
	role1->deleteRole(role2);
}

bool RoleManager::hasLink(string name1, string name2, string domain) {
	name1 = domain + "::" + name1;
	name2 = domain + "::" + name2;

	if (name1 == name2) return true;

	if (!hasRole(name1) || !hasRole(name2)) return false;

	Role* role1 = createRole(name1);
	return role1->hasRole(name2, maxHierarchyLevel);
}

bool RoleManager::hasLink(string name1, string name2) {
	if (name1 == name2) return true;

	if (!hasRole(name1) || !hasRole(name2)) return false;

	Role* role1 = createRole(name1);
	return role1->hasRole(name2, maxHierarchyLevel);
}

vector<string> RoleManager::getRoles(string name, string domain) {
	name = domain + "::" + name;
	
	if (!hasRole(name)) return vector<string>();

	vector<string> roles = createRole(name)->getRoles();

	for (auto itr = roles.begin(); itr != roles.end(); itr++) {
		string temp = *itr;
		*itr = temp.substr(domain.length() + 2, temp.length());
	}

	return roles;
}

vector<string> RoleManager::getRoles(string name) {
	if (!hasRole(name)) return vector<string>();
	vector<string> roles = createRole(name)->getRoles();

	return roles;
}