#include"builtin_operators.h"
#include "../ip/ip.h"

#include <algorithm>
#include<regex>


using namespace std;

const string KEY_ROLEMANAGER = "default_rolemanager";


bool  BuiltinOperators::KeyMatch(string key1, string key2) {
	int i = key2.find_first_of('*');
	if (i == -1)
		return key1 == key2;

	if (key1.size() > i) {
		return key1.substr(0, i) == key2.substr(0, i);
	}
	return key1 == key2.substr(0, i);
}

bool  BuiltinOperators::KeyMatch2(string key1, string key2) {
	
	if (key2.find("/*") != key2.npos) {
		key2 = key2.replace(key2.find("/*"), -1, "/.*");
	}

	regex pattern("(.*):[^/]+(.*)");

	while (true) {
		if (key2.find("/:") == key2.npos) {
			break;
		}
		key2 = regex_replace(key2, pattern, "$1[^/]+$2");
	}

	return regex_match(key1, regex("^" + key2 + "$"));
}

bool  BuiltinOperators::KeyMatch3(string key1, string key2) {
	if (key2.find("/*") != key2.npos) {
		key2 = key2.replace(key2.find("/*"), -1, "/.*");
	}

	regex pattern("(.*)\\{[^/]+\\}(.*)");

	while (true) {
		if (key2.find("/{") == key2.npos) {
			break;
		}
		key2 = regex_replace(key2, pattern, "$1[^/]+$2");
	}

	return regex_match(key1, regex("^" + key2 + "$"));
}

bool  BuiltinOperators::KeyMatch4(string key1, string key2) {

	if (key2.find("/*") != key2.npos)
		key2 = key2.replace(key2.find("/*"),-1, "/.*");

	vector<string> tokens;
	vector<string> values;
	int j = -1;
		
	for (int i = 0; i < key2.size(); i++) {
		char c = key2[i];
		if (c == '{') {
			j = i;
		}
		else if (c == '}') {
			tokens.push_back(key2.substr(j, i + 1 - j));
		}
	}

	regex re("(.*)\\{[^/]+\\}(.*)");
	while (true) {
		if (key2.find("/{") == key2.npos) {
			break;
		}
		key2 = regex_replace(key2, re, "$1\([^/]+\)$2");
	}

	re = regex("^" + key2 + "$");

	std::sregex_iterator iter(key1.begin(), key1.end(), re);
	std::sregex_iterator end;

	while (iter != end)
	{

		for (unsigned i = 0; i < iter->size(); ++i)
		{
			values.push_back((*iter)[i]);
		}
		++iter;
	}

	if (values.size() == 0) {
		return false;
	}

	if (tokens.size() != values.size()-1) {
		throw exception("KeyMatch4: number of tokens is not equal to number of values");
	}

	map<string, vector<string>> m;
	for (int i = 0; i < tokens.size(); i++) {
		if (!m.count(tokens[i])) {
			m[tokens[i]] = vector<string>();
		}

		m[tokens[i]].push_back(values[i+1]);
	}

	for (auto values : m) {
		if (values.second.size() > 1) {
			for (int i = 1; i < values.second.size(); i++) {
				if (values.second[i] != values.second[0]) {
					return false;
				}
			}
		}
	}

	return true;
}


bool  BuiltinOperators::RegexMatch(string key1, string key2) {
	return regex_search(key1,regex(key2));
}

bool  BuiltinOperators::IPMatch(string key1, string key2) {
	IP ip1 = IP(key1);
	IP ip2 = IP(key2);

	if (ip1.isIP()) {
		if (ip2.isIP()) {
			return ip1.Equal(ip2);
		}
		else if (ip2.isCIDR()) {
			return ip2.Contain(ip1);
		}
		else {
			return false;
		}
	}
	return false;
}

bool  BuiltinOperators::GlobMatch(string key1, string key2) {
	return false;
}

bool BuiltinOperators::GFunction(RoleManager* rm, vector<string> ils)
{
	int lenargs = ils.size();
	string name1 = ils[0];
	string name2 = ils[1];

	if (rm == NULL) {
		return name1 == name2;
	}
	else if (lenargs == 2) {
		return rm->HasLink(name1, name2, {});
	}
	else {
		string domain = ils[2];
		rm->PrintRoles();
		return rm->HasLink(name1, name2, { domain });
	}
}

packToken  BuiltinOperators::KeyMatchFunc(TokenMap GlobalMap, TokenMap Scope) {
	return KeyMatch(Scope["A"].asString(), Scope["B"].asString());
}

packToken  BuiltinOperators::KeyMatch2Func(TokenMap GlobalMap, TokenMap Scope) {
	return KeyMatch2(Scope["A"].asString(), Scope["B"].asString());
}
packToken  BuiltinOperators::KeyMatch3Func(TokenMap GlobalMap, TokenMap Scope) {
	return KeyMatch3(Scope["A"].asString(), Scope["B"].asString());
}
packToken  BuiltinOperators::KeyMatch4Func(TokenMap GlobalMap, TokenMap Scope) {
	return KeyMatch4(Scope["A"].asString(), Scope["B"].asString());
}
packToken  BuiltinOperators::RegexMatchFunc(TokenMap GlobalMap, TokenMap Scope) {
	return RegexMatch(Scope["A"].asString(), Scope["B"].asString());
}
packToken  BuiltinOperators::IPMatchFunc(TokenMap GlobalMap, TokenMap Scope) {
	return IPMatch(Scope["A"].asString(), Scope["B"].asString());
}
packToken  BuiltinOperators::GlobMatchFunc(TokenMap GlobalMap, TokenMap Scope) {
	return GlobMatch(Scope["A"].asString(), Scope["B"].asString());
}

packToken BuiltinOperators::GFunctionFunc(TokenMap GlobalMap, TokenMap Scope)
{
	RoleManager* rm = GlobalMap[KEY_ROLEMANAGER].asPtype().rm;

	if (Scope["C"].str() != "None") {
		return GFunction(rm, {Scope["A"].asString(),Scope["B"].asString() ,Scope["C"].asString() });
	}
	else if (Scope["B"].str() != "None") {
		return GFunction(rm, { Scope["A"].asString(),Scope["B"].asString()});
	}
}