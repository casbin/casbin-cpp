#pragma once

#include <map>
#include <vector>
#include <string>
#include <regex>
#include "utils.h"
#include "operator.h"

using namespace std;

class Matcher {
	std::vector<Operator*> knownOperators{ new AND(), new OR(), new EQUALS() };
protected:
	string injectValue(map<string, string>, string);
	string parseString(string);
public:
	string matcherString;
	bool eval(map<string, string>, string);
};