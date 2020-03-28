#pragma once

#ifdef CASBIN_EXPORTS
#define MODEL_API __declspec(dllexport)
#else
#define MODEL_API __declspec(dllimport)
#endif

#include <string>
#include <array>
#include "../config/config.h"
#include "../model/assertion.h"
#include "../util/utils.h"

using namespace std;

class AssertionMap {
public:
	map<string, Assertion*> data = {};
	AssertionMap(string s, Assertion* a) {
		data.insert(make_pair(s, a));
	}
};

class MODEL_API Model {
	Config adapter;
	const map<string, string> sectionNameMap = { {"r", "request_definition"},
	{"p", "policy_definition"},
	{"g", "role_definition"},
	{"e", "policy_effect"},
	{"m", "matchers"} };
	const array<string, 4> requiredSections = { "r", "p", "e", "m" };
protected:
	void loadModel(string);
	void loadModelFromConfig(Config);
	void loadSection(Config cfg, string sec);
	void loadModelFromText(string);
	bool hasSection(string);
public:
	map<string, AssertionMap*> model;
	Model(string fileName) {
		loadModel(fileName);
	}
	bool loadAssertion(Config, string, string);
	bool addDef(string, string, string);
	void printModel();
	void clearPolicy();
	void buildRoleLinks(RoleManager*);
};