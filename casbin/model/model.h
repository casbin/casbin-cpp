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
	unordered_map<string, assertion*> data = {};
	AssertionMap(string s, assertion* a) {
		data.insert(make_pair(s, a));
	}
};

class MODEL_API Model {
	Config adapter;
	const unordered_map<string, string> sectionNameMap = { {"r", "request_definition"},
	{"p", "policy_definition"},
	{"g", "role_definition"},
	{"e", "policy_effect"},
	{"m", "matchers"} };
	const array<string, 4> required_sections_ = { "r", "p", "e", "m" };
protected:
	void load_model(const string&);
	void load_model_from_config(const Config&);
	void load_section(const Config& cfg, const string& sec);
	void load_model_from_text(string);
	bool has_section(const string&);
public:
	unordered_map<string, AssertionMap*> model;

	explicit Model(const string& file_name) {
		load_model(file_name);
	}
	bool load_assertion(Config, const string&, const string&);
	bool add_def(const string&, const string&, const string&);
	void print_model();
	void clear_policy();
	void build_role_links(role_manager*);
};