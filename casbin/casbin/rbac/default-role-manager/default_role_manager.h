#pragma once

#ifdef CASBIN_EXPORTS
#define DEFAULT_ROLE_MANAGER_API __declspec(dllexport)
#define ROLE_API __declspec(dllexport)
#else
#define DEFAULT_ROLE_MANAGER_API __declspec(dllimport)
#define ROLE_API __declspec(dllimport)
#endif

#include"../role_manager.h"
#include <map>
using namespace std;

typedef bool (*MatchingFunc) (const string& arg1,const string& arg2);

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

class DEFAULT_ROLE_MANAGER_API DefaultRoleManager : public RoleManager{
public:
	map<string,Role*> allRoles;
	int maxHierarchyLevel;
	bool hasPattern;
	MatchingFunc matchingFunc;

	DefaultRoleManager(const int& maxHierarchyLevel);
	void AddMatchingFunc(const string& name,MatchingFunc fn);
	bool hasRole(const string& name);
	Role* createRole(const string& name);
	void Clear();
	void Addlink(const string& name1, const string& name2, initializer_list<string> domain);
	void DeleteLink(const string& name1, const  string& name2, initializer_list<string> domain);
	bool HasLink(const string& name1, const  string& name2, initializer_list<string> domain);
	vector<string> GetRoles(const string& name,initializer_list<string> domain);
	vector<string> GetUsers(const string& name, initializer_list<string> domain);
	void PrintRoles();

};