#pragma once

#ifdef CASBIN_EXPORTS
#define MODEL_API __declspec(dllexport)
#else
#define MODEL_API __declspec(dllimport)
#endif

#include <string>
#include <array>
#include "config.h"
#include "assertion.h"
#include "utils.h"

using namespace std;

class AssertionMap {
public:
	map<string, Assertion*> data;
	AssertionMap(string s, Assertion* a) {
		data.insert({ s, a });
	}
};

class MODEL_API Model {
	Config adapter;
	map<string, AssertionMap*> model;
	const map<string, string> sectionNameMap = { {"r", "request_definition"},
	{"p", "policy_definition"},
	{"g", "role_definition"},
	{"e", "policy_effect"},
	{"m", "matchers"} };
	const array<string, 4> requiredSections = { "r", "p", "e", "m" };

public:
	friend bool loadAssertion(Model, Config, string, string);
	bool addDef(string, string, string);
};