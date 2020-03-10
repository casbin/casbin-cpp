#pragma once

#include <map>
#include <vector>
#include <string>
#include <regex>
#include "utils.h"
#include "Operator.h"

using namespace std;

class Matcher {
	string policyeffect;
	std::vector<Operator*> knownOperators{ new AND(), new OR(), new EQUALS() };
public:
	string matcherString;
	bool mergeDecisions(vector<string>);
	string injectValue(map<string, vector<string>>, string, string, string);
	string parseString(string);
	bool addPolicyEffect(string);
};