#pragma once

#ifdef CASBIN_EXPORTS
#define MATCHER_API __declspec(dllexport)
#else
#define MATCHER_API __declspec(dllimport)
#endif

#include <unordered_map>
#include <utility>
#include <vector>
#include <string>
#include <regex>
#include <functional>
#include "utils.h"
#include "operator.h"

using namespace std;

class MATCHER_API matcher {
	const std::vector<Operator*> known_operators_{ new AND(), new OR(), new EQUALS() };
	unordered_map<string, function<bool(string, string)>> functions_;
protected:
	string inject_value(const unordered_map<string, string>&, string) const;
	string parse_string(string) const;
	string parse_functions(unordered_map<string, string>, string);
public:
	matcher();

	explicit matcher(unordered_map<string, function<bool(string, string)>> temp) {
		functions_ = std::move(temp);
	}
	string matcher_string;
	bool eval(const unordered_map<string, string>&, string);
};