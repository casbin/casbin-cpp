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

// InitWithFile initializes an enforcer with a model file and a policy file.
string Enforcer::InitWithFile(string modelPath,string policyPath) {
	Enforcer *e;
	Adapter a;
	// auto a = fileadapter.NewAdapter(policyPath);
	return e->InitWithAdapter(modelPath, a);
}

// InitWithAdapter initializes an enforcer with a database adapter.
string Enforcer::InitWithAdapter(string modelPath, Adapter adapter) {
	string err;
	Model model, m;
	Enforcer *e;

	// tie(m, err) = model.NewModelFromFile(modelPath);
	if (err != " ") {
		return err;
	}

	err = e->InitWithModelAndAdapter(m, adapter);
	if (err != " ") {
		return err;
	}

	e->modelPath = modelPath;
	return " ";
}

// InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
string Enforcer::InitWithModelAndAdapter(Model m,Adapter adapter) {
	Enforcer *e;
	e->adapter = adapter;

	e->model = m;
	// e->model.PrintModel();
	Model model;
	// e->fm = model.LoadFunctionMap();

	e->initialize();

	// Do not initialize the full policy when using a filtered adapter

	/*if(type_id(adapter)==type_id(FilteredAdapter)) {
		adapter fa;
		bool ok = true;
	}
	fa = e->adapter;  
	if (e->adapter != adapter() && (!ok || ok && !fa.IsFiltered())) {
		string err = e->LoadPolicy();
		if err != " " {
			return err;
		}
	}
*/
	return " ";
}