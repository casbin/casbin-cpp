/*
* Copyright 2020 The casbin Authors. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#pragma once

#ifdef CASBIN_EXPORTS
#define ENFORCER_API __declspec(dllexport)
#else
#define ENFORCER_API __declspec(dllimport)
#endif

#include <string>
#include <vector>
#include "util/builtin_operators.h"
#include "model/model.h"
#include "effect/effector.h"
#include "util/matcher.h"
#include "persist/file_adapter.h"
#include "rbac/role_manager.h"
#include <any>

using namespace std;

class ENFORCER_API Enforcer {
	string model_path_;
	Model* model_{};
	effector* eft_{};
	Adapter* adapter_{};
	role_manager* rm_{};

	bool enabled_{};
	bool auto_save_{};
	bool auto_build_role_links_{};
	bool auto_notify_watcher_{};

protected:
	void initialize();
	void init_with_file(const string&, const string&);
	void init_with_adapter(const string&, Adapter*);
	void init_with_model_and_adapter(Model*, Adapter*);
	[[nodiscard]] auto run_enforce(unordered_map<string, string>) const -> bool;
public:
	explicit Enforcer(const string& model_file) {
		init_with_file(model_file, "");
	}
	Enforcer(const string& model_file, const string& policy_file) {
		init_with_file(model_file, policy_file);
	}
	Enforcer(const string& model_file, Adapter* policy_adapter) {
		init_with_adapter(model_file, policy_adapter);
	}

	template <typename T1, typename T2, typename T3>
	bool enforce(T1 sub, T2 obj, T3 act) {
		unordered_map<string, string> request;
		auto rtokens = model_->model.find("r")->second->data.find("r")->second->tokens;

		if (typeid(unordered_map<string, string>).name() == typeid(T1).name()) {
			for (auto& kv : any_cast<unordered_map<string, string>>(sub)) {
				request.insert({ rtokens[0] + "_" + kv.first, kv.second });
			}
		}
		else {
			request.insert({ rtokens[0], any_cast<string>(sub) });
		}

		if (typeid(unordered_map<string, string>).name() == typeid(T2).name()) {
			for (auto& kv : any_cast<unordered_map<string, string>>(obj)) {
				request.insert({ rtokens[1] + "_" + kv.first, kv.second });
			}
		}
		else {
		request.insert({ rtokens[1], any_cast<string>(obj) });
		}

		if (typeid(unordered_map<string, string>).name() == typeid(T3).name()) {
			for (auto& kv : any_cast<unordered_map<string, string>>(act)) {
				request.insert({ rtokens[2] + "_" + kv.first, kv.second });
			}
		}
		else {
		request.insert({ rtokens[2], any_cast<string>(act) });
		}

		return run_enforce(request);
	}

	//bool enforce(unordered_map<string, string> sub, unordered_map<string, string> obj, unordered_map<string, string> act);
	[[nodiscard]] Model* get_model() const;
	void load_model();
	void set_model(Model m);
	[[nodiscard]] auto get_adapter() const -> Adapter*;
	void set_adapter(Adapter*);
	[[nodiscard]] role_manager* get_role_manager() const;
	void set_role_manager(role_manager*);
	void clear_policy() const;

	// Management API
	auto get_all_subjects() -> vector<string>;
	auto get_all_named_subjects(string) -> vector<string>;
	auto get_all_objects() -> vector<string>;
	auto get_all_named_objects(string) -> vector<string>;
	auto get_all_actions() -> vector<string>;
	auto get_all_named_actions(string) -> vector<string>;
	auto get_all_roles() -> vector<string>;
	auto get_all_named_roles(string) -> vector<string>;
	vector<string> get_policy() const;
	vector<string> get_filtered_policy(int, string);
	vector<string> get_named_policy(string);
	vector<string> getFilteredNamedPolicy(string, int, string);
	vector<string> getGroupingPolicy();
	vector<string> getFilteredGroupingPolicy(int, string);
	vector<string> getNamedGroupingPolicy(string);
	vector<string> getFilteredNamedGroupingPolicy(string, int, string);
	bool hasPolicy(string, string, string);
	bool hasNamedPolicy(string, string, string, string);
	bool addPolicy(string, string, string);
	bool addNamedPolicy(string, string, string, string);
	bool removePolicy(string, string, string);
	bool removeFilteredPolicy(int, string, string, string);
	bool removeNamedPolicy(string, string, string, string);
	bool removeFilterdNamedPolicy(string, int, string, string, string);
	bool hasGroupingPolicy(string, string, string);
	bool hasNamedGroupingPolicy(string, string, string);
	bool addGroupingPolicy(string, string);
	bool addNamedGroupingPolicy(string, string, string);
	bool removeGroupingPolicy(string, string);
	bool removeFilteredGroupingPolicy(int, string);
	bool removeNamedGroupingPolicy(string, string);
	bool removeFilteredNamedGroupingPolicy(string, int, string);
	bool addFunction(function<bool(string, string)>);

	// RBAC API
	vector<string> getRolesForUser(string);
	vector<string> getUsersForRole(string);
	bool hasRoleforUser(string, string);
	bool addRoleforUser(string, string);
	bool deleteRoleForUser(string, string);
	bool deleteUser(string);
	bool deleteRole(string);
	bool deletePermission(string);
	bool addPermissionForUser(string, string);
	bool deletePermissionForUser(string, string);
	bool deletePermissionsForUser(string);
	vector<string> getPermissionsForUser(string);
	bool hasPermissionForUser(string, string);
	vector<string> getImplicitRolesForUser(string);
	vector<vector<string>> getImplicitPermissionsForUser(string);
};