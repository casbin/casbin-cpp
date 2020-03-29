#pragma once

#ifdef CASBIN_EXPORTS
#define MATCHER_API __declspec(dllexport)
#else
#define MATCHER_API __declspec(dllimport)
#endif

#include <map>
#include <vector>
#include <string>
#include <regex>
#include <functional>
#include "utils.h"
#include "operator.h"

using namespace std;

class MATCHER_API Matcher {
	const std::vector<Operator*> knownOperators{ new AND(), new OR(), new EQUALS() };
	map<string, function<bool(string, string)>> functions;
protected:
	string injectValue(map<string, string>, string);
	string parseString(string);
	string parseFunctions(map<string, string>, string);
public:
	Matcher() {
	}
	Matcher(map<string, function<bool(string, string)>> temp) {
		functions = temp;
	}
	string matcherString;
	bool eval(map<string, string>, string);
};