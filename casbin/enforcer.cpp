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

void Enforcer::initWithFile(string modelFile, string policyPath) {
	FileAdapter* a = new FileAdapter(policyPath);
	initWithAdapter(modelFile, a);
}

void Enforcer::initWithAdapter(string modelFile, Adapter* a) {
	Model* m = new Model(modelFile);
	initWithModelAndAdapter(m, a);
}

void Enforcer::initWithModelAndAdapter(Model* m, Adapter* a) {
	adapter = a;
	model = m;
	a->loadPolicy(model);

	initialize();
}

void Enforcer::initialize() {
	rm = new RoleManager();
	eft = new Effector();
}

void printStructuret(map<string, string> structure) {
	for (auto& kv : structure) {
		cout << kv.first << ":" << kv.second;
	}
}

bool Enforcer::enforce(string sub, string obj, string act) {
	vector<Effect> effects;
	map<string, string> structure;
	string expString = model->model.find("m")->second->data.find("m")->second->value;
	Matcher matcher;

	vector<string> rtokens = model->model.find("r")->second->data.find("r")->second->tokens;
	vector<string> ptokens = model->model.find("p")->second->data.find("p")->second->tokens;

	for (string pol : getPolicy()) {
		structure.insert({ rtokens[0], sub });
		structure.insert({ rtokens[1], obj });
		structure.insert({ rtokens[2], act });

		int i = 0;
		vector<string> parr = split(pol, ',');
		for (string ptoken : ptokens) {
			structure.insert({ ptoken, parr[i] });
			i++;
		}

		bool result = matcher.eval(structure, expString);
		if (result) effects.push_back(Effect::Allow);
		else effects.push_back(Effect::Deny);

		structure.clear();
	}

	cout << model->model.find("e")->second->data.find("e")->second->value;

	return eft->mergeEffects(model->model.find("e")->second->data.find("e")->second->value, effects);
}

Model* Enforcer::getModel() {
	return model;
}

void Enforcer::setModel(Model m) {
	model = &m;
	initialize();
}

vector<string> Enforcer::getPolicy() {
	vector<string> temp;
	AssertionMap* astm = model->model.find("p")->second;
	Assertion* ast = astm->data.find("p")->second;

	for (vector<string> str : ast->policy) {
		temp.push_back(join(str, ','));
	}

	return temp;
}