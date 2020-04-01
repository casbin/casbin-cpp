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

#include "enforcer.h"

auto Enforcer::init_with_file(const string& model_file, const string& policy_path) -> void
{
	model_path_ = model_file;
	const auto a = new file_adapter(policy_path);
	init_with_adapter(model_file, a);
}

void Enforcer::init_with_adapter(const string& model_file, Adapter* a) {
	const auto m = new Model(model_file);
	init_with_model_and_adapter(m, a);
}

void Enforcer::init_with_model_and_adapter(Model* m, Adapter* a) {
	adapter_ = a;
	model_ = m;
	a->load_policy(model_);

	initialize();
}

void Enforcer::initialize() {
	rm_ = new role_manager();
	eft_ = new effector();

	enabled_ = true;
	auto_save_ = true;
	auto_build_role_links_ = true;
	auto_notify_watcher_ = true;

	model_->build_role_links(rm_);
}

bool Enforcer::run_enforce(unordered_map<string, string> request) const
{
	vector<effect> effects;
	unordered_map<string, string> structure;
	unordered_map<string, function<bool(string, string)>> functions;
	const auto exp_string = model_->model.find("m")->second->data.find("m")->second->value;

	functions.insert(make_pair("g", generate_g_function(rm_)));
	functions.insert(make_pair("keyMatch", key_match));
	functions.insert(make_pair("keyMatch2", key_match2));
	functions.insert(make_pair("keyMatch4", key_match4));
	functions.insert(make_pair("regexMatch", regex_match));
	functions.insert(make_pair("ipMatch", ip_match));

	matcher matcher(functions);
	auto ptokens = model_->model.find("p")->second->data.find("p")->second->tokens;


	for (const auto& pol : get_policy()) {
		structure.insert(request.begin(), request.end());

		auto i = 0;
		auto parr = split(pol, ',');
		for (const string& ptoken : ptokens) {
			structure.insert({ ptoken, parr[i] });
			i++;
		}

		const auto result = matcher.eval(structure, exp_string);
		if (result) effects.push_back(effect::allow);
		else effects.push_back(effect::deny);

		structure.clear();
	}

	return effector::merge_effects(model_->model.find("e")->second->data.find("e")->second->value, effects);
}

auto Enforcer::get_model() const -> Model*
{
	return model_;
}

auto Enforcer::set_model(Model m) -> void
{
	model_ = &m;
	initialize();
}

auto Enforcer::get_policy() const -> vector<string>
{
	vector<string> temp;
	auto astm = model_->model.find("p")->second;
	auto ast = astm->data.find("p")->second;

	for (const auto& str : ast->policy) {
		temp.push_back(join(str, ','));
	}

	return temp;
}

void Enforcer::load_model() {
	model_ = new Model(model_path_);
	initialize();
}

auto Enforcer::get_adapter() const -> Adapter*
{
	return adapter_;
}

void Enforcer::set_adapter(Adapter* a) {
	adapter_ = a;
}

role_manager* Enforcer::get_role_manager() const
{
	return rm_;
}

void Enforcer::set_role_manager(role_manager* rolem) {
	rm_ = rolem;
}

void Enforcer::clear_policy() const
{
	model_->clear_policy();
}

