#pragma once

#ifdef CASBIN_EXPORTS
#define DEFAULT_ROLE_MANAGER_API __declspec(dllexport)
#else
#define DEFAULT_ROLE_MANAGER_API __declspec(dllimport)
#endif

#include"../role_manager.h"
#include <map>
using namespace std;

class DEFAULT_ROLE_MANAGER_API DefaultRoleManager : public RoleManager{
public:

	DefaultRoleManager(const int& maxHierarchyLevel);
	bool hasRole(const string& name);
	Role* createRole(const string& name);
	void Clear();
	void Addlink(const string& name1, const string& name2, initializer_list<string> domain);
	void DeleteLink(const string& name1, const  string& name2, initializer_list<string> domain);
	bool HasLink(const string& name1, const  string& name2, initializer_list<string> domain);
	vector<string> GetRoles(const string& name,initializer_list<string> domain);
	vector<string> GetUsers(const string& name, initializer_list<string> domain);
	void AddMatchingFunc(const string& name1, bool (*func) (string arg1, string arg2));
	void PrintRoles();

};
