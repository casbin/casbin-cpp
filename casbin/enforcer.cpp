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

#include "pch.h"
#include "enforcer.h"

bool Enforcer::enforce(string sub, string obj, string act) {
	return false;
}


void Enforcer::initialize() {
	Enforcer* e;
	// e.rm = defaultrolemanager.NewRoleManager(10)
	// e.eft = effect.NewDefaultEffector()
	// e.watcher = nil

	e.enabled = true;
	e.autoSave = true;
	e.autoBuildRoleLinks = true;
	e.autoNotifyWatcher = true;
}

// LoadModel reloads the model from the model CONF file.
// Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
string Enforcer::loadModel() {
	Enforcer* e;
	string err;
	// Model model;
    // tie(e.model, err) = model.NewModelFromFile(e.modelPath);
	if(err != " ") {
		return err;
	}

	// e.model.PrintModel();
	// e.fm = model.LoadFunctionMap();

	e.initialize();

	return " ";
}