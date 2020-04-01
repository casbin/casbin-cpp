#include "role_manager.h"

#include <utility>

auto new_role(const string& name) -> role*
{
	auto temp = new role();
	temp->name = name;

	return temp;
}

void role::add_role(role* r) {
	for (auto temp : roles) {
		if (temp->name == r->name) return;
	}
	roles.push_back(r);
}

void role::delete_role(role* r) {
	for (auto itr = roles.begin(); itr != roles.end(); ++itr) {
		const auto temp = *itr;
		if (temp->name == r->name) {
			roles.erase(itr);
			return;
		}
	}
}

auto role::has_role(const string& n, const int hierarchy_level) -> bool
{
	if (name == n) return true;

	if (hierarchy_level <= 0) return false;

	for (auto itr = roles.begin(); itr != roles.end(); ++itr) {
		auto temp = *itr;
		if (temp->has_role(n, hierarchy_level - 1)) return true;
	}

	return false;
}

vector<string> role::get_roles() {
	vector<string> names;
	for (auto temp : roles) {
		names.push_back(temp->name);
	}

	return names;
}

void role_manager::add_matching_func(function<bool(string, string)> fn) {
	matching_func_ = std::move(fn);
	has_pattern_ = true;
}

auto role_manager::has_role(const string& name) -> bool
{
	if (has_pattern_) {
		for (auto itr = all_roles_.begin(); itr != all_roles_.end(); ++itr) {
			if (matching_func_(name, itr->first)) {
				return true;
			}
		}
	}
	else {
		const auto itr = all_roles_.find(name);
		return itr != all_roles_.end() ? true : false;
	}

	return false;
}

role* role_manager::create_role(const string& name) {
	role* r;
	if (all_roles_.find(name) == all_roles_.end()) {
		r = new_role(name);
		all_roles_.insert(make_pair(name, r));
	}
	else {
		r = all_roles_.find(name)->second;
	}

	if (has_pattern_) {
		for (auto itr = all_roles_.begin(); itr != all_roles_.end(); ++itr) {
			if (matching_func_(name, itr->first) && name != itr->first) {
				const auto role1 = itr->second;
				r->add_role(role1);
			}
		}
	}

	return r;
}

void role_manager::clear() {
	all_roles_.clear();
}

auto role_manager::add_link(string name1, string name2, const string& domain) -> void
{
	name1.insert(0, domain + "::");
	name2.insert(0, domain + "::");

	auto role1 = create_role(name1);
	const auto role2 = create_role(name2);
	role1->add_role(role2);
}

auto role_manager::add_link(const string& name1, const string& name2) -> void
{
	auto role1 = create_role(name1);
	const auto role2 = create_role(name2);
	role1->add_role(role2);
}

auto role_manager::delete_link(string name1, string name2, const string& domain) -> void
{
	name1.insert(0, domain + "::");
	name2.insert(0, domain + "::");

	auto role1 = create_role(name1);
	const auto role2 = create_role(name2);
	role1->delete_role(role2);
}

auto role_manager::delete_link(const string& name1, const string& name2) -> void
{
	auto role1 = create_role(name1);
	const auto role2 = create_role(name2);
	role1->delete_role(role2);
}

bool role_manager::has_link(string name1, string name2, const string& domain) {
	name1 = domain + "::" + name1;
	name2 = domain + "::" + name2;

	if (name1 == name2) return true;

	if (!has_role(name1) || !has_role(name2)) return false;

	auto role1 = create_role(name1);
	return role1->has_role(name2, max_hierarchy_level_);
}

auto role_manager::has_link(const string& name1, const string& name2) -> bool
{
	if (name1 == name2) return true;

	if (!has_role(name1) || !has_role(name2)) return false;

	auto role1 = create_role(name1);
	return role1->has_role(name2, max_hierarchy_level_);
}

auto role_manager::get_roles(string name, const string& domain) -> vector<string>
{
	name = domain + "::" + name;
	
	if (!has_role(name)) return vector<string>();

	auto roles = create_role(name)->get_roles();

	for (auto itr = roles.begin(); itr != roles.end(); ++itr) {
		auto temp = *itr;
		*itr = temp.substr(domain.length() + 2, temp.length());
	}

	return roles;
}

auto role_manager::get_roles(const string& name) -> vector<string>
{
	if (!has_role(name)) return vector<string>();
	auto roles = create_role(name)->get_roles();

	return roles;
}
