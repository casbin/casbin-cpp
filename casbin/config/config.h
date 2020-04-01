#pragma once

#ifdef CASBIN_EXPORTS
#define CONFADAPTER_API __declspec(dllexport)
#else
#define CONFADAPTER_API __declspec(dllimport)
#endif

#include <unordered_map>
#include <string>
#include <regex>
#include "../util/utils.h"

using namespace std;

class CONFADAPTER_API Config {
	unordered_map<string, unordered_map<string, string>> data_;
public:
	Config();

	explicit Config(const string& conf_name);

	auto parse_stream(stringstream&) -> void;
	auto read_from_file(const string&) -> void;
	auto read_from_text(const string&) -> void;
	auto add_config(string, string, string) -> bool;
	auto get(string) -> string;
	auto set(const string&, const string&) -> void;
	auto strings(const string&) -> vector<string>;
};