#pragma once

#ifdef CASBIN_EXPORTS
#define ROLE_API __declspec(dllexport)
#define ROLEMAMAGER_API __declspec(dllexport)
#else
#define ROLE_API __declspec(dllexport)
#define ROLEMAMAGER_API __declspec(dllimport)
#endif

#include<string>
#include<vector>
#include<initializer_list>
#include<exception>
#include<map>

using std::vector;
using std::string;
using std::initializer_list;
using std::map;

//typedef bool (*MatchingFunc) (string arg1, string arg2);

class ROLE_API Role {
public:
	string name;
	vector<Role*> roles;

	Role(const string& name);
	void addRole(Role* role);
	void deleteRole(Role* role);
	bool hasRole(const string& name, const int& hierarchyLevel);
	bool hasDirectRole(const string& name);
	string toString();
	vector<string> getRoles();
};

class ROLEMAMAGER_API RoleManager {
public:
	map<string, Role*> allRoles;
	int maxHierarchyLevel;
	bool hasPattern;
	bool (*matchingFunc) (string arg1, string arg2);

	RoleManager() {};
	virtual void Clear() = 0;
	virtual void Addlink(const string& name1, const string& name2, initializer_list<string> domain) = 0;
	virtual void DeleteLink(const string& name1, const string& name2, initializer_list<string> domain) = 0;
	virtual bool HasLink(const string& name1, const string& name2, initializer_list<string> domain) = 0;
	virtual vector<string> GetRoles(const string& name, initializer_list<string> domain) = 0;
	virtual vector<string> GetUsers(const string& name, initializer_list<string> domain) = 0;
	virtual void AddMatchingFunc(const string& name1, bool (*func) (string arg1, string arg2)) = 0;
	virtual void PrintRoles() = 0;
};