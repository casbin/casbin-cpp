#pragma once

#ifdef CASBIN_EXPORTS
#define ROLEMAMAGER_API __declspec(dllexport)
#else
#define ROLEMAMAGER_API __declspec(dllimport)
#endif

#include<string>
#include<vector>
#include<initializer_list>
#include"../errors/exceptions.h"

using std::vector;
using std::string;
using std::initializer_list;

class ROLEMAMAGER_API RoleManager {
public:
	RoleManager() {};
	virtual Error Clear() = 0;
	virtual Error Addlink(const string& name1, const string& name2, initializer_list<string> domain) = 0;
	virtual Error DeleteLink(const string& name1, const string& name2, initializer_list<string> domain) = 0;
	virtual Error HasLink(bool& res,const string& name1, const string& name2, initializer_list<string> domain) = 0;
	virtual Error GetRoles(vector<string>& res, const string& name, initializer_list<string> domain) = 0;
	virtual Error GetUsers(vector<string>& res, const string& name, initializer_list<string> domain) = 0;
	virtual Error PrintRoles() = 0;
};