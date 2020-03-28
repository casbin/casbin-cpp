#pragma once

#include <functional>
#include "utils.h"
#include "../rbac/role_manager.h"

using namespace std;

bool keyMatch(string arg1, string arg2)
{
	arg2 = trim(arg2);
	arg1 = trim(arg1);

	vector<string> arg2arr = split(arg2, '/');
	vector<string> arg1arr = split(arg1, '/');

	vector<string>::iterator itr = arg2arr.begin();
	int i = 0;
	while (itr != arg2arr.end())
	{
		if (*itr == "*")
		{
			i++;
			itr++;
			continue;
		}
		if (i >= arg1arr.size())
			return false;
		if (*itr != arg1arr.at(i))
			return false;
		i++;
		itr++;
	}

	return true;
}

bool keyMatch2(string arg1, string arg2)
{
	arg2 = trim(arg2);
	arg1 = trim(arg1);

	vector<string> arg2arr = split(arg2, '/');
	vector<string> arg1arr = split(arg1, '/');

	int i = 0;
	for (string ele : arg2arr)
	{
		if (ele.at(0) == ':')
		{
			i++;
			continue;
		}
		if (i >= arg1arr.size())
			return false;
		if (ele != arg1arr.at(i))
			return false;
		i++;
	}

	return true;
}

bool keyMatch4(string arg1, string arg2)
{
	arg2 = trim(arg2);
	arg1 = trim(arg1);

	vector<string> arg2arr = split(arg2, '/');
	vector<string> arg1arr = split(arg1, '/');
	map<string, string> urlKey;

	int i = 0;
	for (string ele : arg2arr)
	{
		if (i >= arg1arr.size())
			return false;
		if (ele.at(0) == '{' && ele.at(ele.length() - 1) == '}')
		{
			ele = ele.erase(0, 1);
			ele.erase(ele.length() - 1, 1);
			if (urlKey.find(ele) == urlKey.end())
			{
				urlKey.insert(pair<string, string>(ele, arg1arr.at(i)));
			}
			else
			{
				if (urlKey.find(ele)->second != arg1arr.at(i))
					return false;
			}
			i++;
			continue;
		}
		if (ele != arg1arr.at(i))
			return false;
		i++;
	}

	return true;
}

inline bool regexMatch(string arg1, string arg2)
{
	regex e(arg2);
	if (regex_search(arg1, e)) return true;
	return false;
}

function<bool(string, string)> generateGFunction(RoleManager* rm) {
	auto func = [](RoleManager* rm, string name1, string name2) { 
		if (rm == NULL) return name1 == name2;
		bool result = rm->hasLink(name1, name2);
		return result;
	};

	return bind(func, rm, placeholders::_1, placeholders::_2);
}