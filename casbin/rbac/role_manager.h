#pragma once

#ifdef CASBIN_EXPORTS
#define ROLEMANAGER_API __declspec(dllexport)
#else
#define ROLEMANAGER_API __declspec(dllimport)
#endif

#include <vector>
#include <deque>
#include <unordered_map>
#include <string>
#include <functional>

using namespace std;

struct role {
	string name;
	deque<role*> roles;
	auto add_role(role*) -> void;
	auto delete_role(role*) -> void;
	auto has_role(const string&, int hierarchy_level) -> bool;
	auto get_roles() -> vector<string>;
};

class ROLEMANAGER_API role_manager {
	unordered_map<string, role*> all_roles_;
	function<bool(string, string)> matching_func_;
	bool has_pattern_ = false;
	int max_hierarchy_level_ = 10;
public:
	auto add_matching_func(function<bool(string, string)>) -> void;
	auto has_role(const string&) -> bool;
	auto clear() -> void;
	auto create_role(const string&) -> role*;
	auto add_link(string, string, const string&) -> void;
	auto add_link(const string&, const string&) -> void;
	auto delete_link(string, string, const string&) -> void;
	auto delete_link(const string&, const string&) -> void;
	auto has_link(string, string, const string&) -> bool;
	auto has_link(const string&, const string&) -> bool;
	auto get_roles(string, const string&) -> vector<string>;
	auto get_roles(const string&) -> vector<string>;
};
