#include "default_role_manager.h"
#include "../role_manager.h"
#include "../../errors/exceptions.h"
#include <iostream>

Role::Role(const string& name)
{
	this->name = name;
}

void Role::addRole(Role* role)
{
	for (auto rr : roles)
	{
		if (rr->name == role->name) {
			return;
		}
	}
	roles.push_back(role);
}

void Role::deleteRole(Role* role)
{
	for (vector<Role*>::iterator it = roles.begin(); it != roles.end();)
	{
		if ((*it)->name == role->name)
		{
			it = roles.erase(it);
			return;
		}
	}
}

bool Role::hasRole(const string& name, const int& hierarchyLevel)
{
	if (this->name == name){
		return true;
	}

	if ( hierarchyLevel <= 0 ){
		return false;
	}

	for (auto role : roles){
		if (role->hasRole(name, hierarchyLevel - 1)) {
			return true;
		}
	}
	return false;
}

bool Role::hasDirectRole(const string& name)
{
	for (auto role : roles){
		if (role->name == name ) {
			return true;
		}
	}

	return false;
}

string Role::toString()
{
	if (roles.size() == 0 ){
		return "";
	}

	string res;
	res += name;
	res += " < ";
	if (roles.size() != 1 ){
		res += "(";
	}

	for (int i = 0; i < roles.size(); i++)
	{
		if (i == 0) {
			res += roles[i]->name;
		}
		else {
			res += ", ";
			res += roles[i]->name;
		}
	}

	if (roles.size() != 1) {
		res += ")";
	}

	return res;
}

vector<string> Role::getRoles()
{
	vector<string> names;
	for (auto role : roles) {
		names.push_back(role->name);
	}
	return names;
}

DefaultRoleManager::DefaultRoleManager(const int& maxHierarchyLevel)
{
	this->maxHierarchyLevel = maxHierarchyLevel;
	hasPattern = false;
}

void DefaultRoleManager::AddMatchingFunc(const string& name, MatchingFunc fn)
{
	hasPattern = true;
	matchingFunc = fn;
}

bool DefaultRoleManager::hasRole(const string& name)
{
	bool ok = false;
	if (hasPattern) {
		for (map<string,Role*>::iterator it=allRoles.begin();it!=allRoles.end();it++)
		{
			if (matchingFunc(name, it->first)) {
				ok = true;
				break;
			}
		}
	} else {
		ok = allRoles.count(name);
	}

	return ok;
}

Role* DefaultRoleManager::createRole(const string& name)
{
	Role* role;
	if (allRoles.count(name)) {
		role = allRoles[name];
	}
	else {
		role = new Role(name);
		allRoles[name] = role;
	}

	if (hasPattern) {
		for (map<string, Role*>::iterator it = allRoles.begin(); it != allRoles.end(); it++)
		{
			if (matchingFunc(name, it->first) && name!= it->first) {
				Role* role1;
				if (allRoles.count(it->first)) {
					role1 = allRoles[it->first];
				}
				else {
					role1 = new Role(it->first);
					allRoles[it->first] = role1;
				}
				role->addRole(role1);
				break;
			}
		}
	}
	return role;
}

Error DefaultRoleManager::Clear()
{
	for (auto role : allRoles)
	{
		delete role.second;
	}
	allRoles.clear();
	return Error();
}

Error DefaultRoleManager::Addlink(const string& name1, const string& name2, initializer_list<string> domain)
{
	if (domain.size() == 1) {
		string name1 = *(domain.begin()) + "::" + name1;
		string name2 = *(domain.begin()) + "::" + name2;
	}
	else if (domain.size() > 1) {
		return Error("ERR_DOMAIN_PARAMETER");
	}

	Role* role1 = createRole(name1);
	Role* role2 = createRole(name2);
	role1->addRole(role2);

	return Error();
}


Error DefaultRoleManager::DeleteLink(const string& name1, const string& name2, initializer_list<string> domain)
{
	if (domain.size() == 1) {
		string name1 = *(domain.begin()) + "::" + name1;
		string name2 = *(domain.begin()) + "::" + name2;
	}
	else if (domain.size() > 1) {
		return Error("ERR_DOMAIN_PARAMETER");
	}

	if (!hasRole(name1) || hasRole(name2)) {
		return Error("ERR_NAMES12_NOTFOUND");
	}


	Role* role1 = createRole(name1);
	Role* role2 = createRole(name2);
	role1->deleteRole(role2);
	return Error();
}

Error DefaultRoleManager::HasLink(bool& res, const string& name1, const  string& name2, initializer_list<string> domain)
{
	if (domain.size() == 1) {
		string name1 = *(domain.begin()) + "::" + name1;
		string name2 = *(domain.begin()) + "::" + name2;
	}
	else if (domain.size() > 1) {
		res = false;
		return Error("ERR_DOMAIN_PARAMETER");
	}

	if (name1 == name2) {
		res = true;
		return Error();
	}

	if (!hasRole(name1) || !hasRole(name2)) {
		res = false;
		return Error();
	}

	Role* role1 = createRole(name1);
	res = role1->hasRole(name2, maxHierarchyLevel);
	return Error();
}

Error DefaultRoleManager::GetRoles(vector<string>& res, const string& name, initializer_list<string> domain)
{
	vector<string> roles;
	if (domain.size() == 1) {
		string name = *(domain.begin()) + "::" + name;
	}
	else if (domain.size() > 1) {
		res = roles;
		return Error("ERR_DOMAIN_PARAMETER");
	}


	if (!hasRole(name)) {
		res = roles;
		return Error();
	}
	roles = createRole(name)->getRoles();
	if (domain.size() == 1) {
		for (auto role : roles)
		{
			role = role.substr((domain.begin())->size() + 2);
		}
	}
	res = roles;
	return Error();
}

Error DefaultRoleManager::GetUsers(vector<string>& res, const string& name, initializer_list<string> domain)
{
	vector<string> names;
	if (domain.size() == 1) {
		string name = *(domain.begin()) + "::" + name;
	}
	else if (domain.size() > 1) {
		res = names;
		return Error("ERR_DOMAIN_PARAMETER");
	}

	for (auto role : allRoles) {
		if (role.second->hasDirectRole(name)) {
			names.push_back(role.second->name);
		}
	}

	if (domain.size() == 1) {
		for (auto n : names)
		{
			n = n.substr((domain.begin())->size() + 2);
		}
	}
	res = names;
	return Error();
}

Error DefaultRoleManager::PrintRoles()
{
	return Error();
}
