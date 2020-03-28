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
#include <functional>
#include "util/utils.h"
#include "util/builtin_operators.h"
#include "model/model.h"
#include "effect/effector.h"
#include "util/matcher.h"
#include "persist/file_adapter.h"
#include "rbac/role_manager.h"

using namespace std;

class ENFORCER_API Enforcer {
	string modelPath;
	Model* model;
	Effector* eft;
	Adapter* adapter;
	RoleManager* rm;

protected:
	void initialize();
	void initWithFile(string, string);
	void initWithAdapter(string, Adapter*);
	void initWithModelAndAdapter(Model*, Adapter*);
public:
	Enforcer(string modelFile) {
		initWithFile(modelFile, "");
	}
	Enforcer(string modelFile, string policyFile) {
		initWithFile(modelFile, policyFile);
	}
	Enforcer(string modelFile, Adapter* policyAdapter) {
		initWithAdapter(modelFile, policyAdapter);
	}

	bool enforce(string sub, string obj, string act);
	Model* getModel();
	void loadModel();
	void setModel(Model m);
	Adapter* getAdapter();
	void setAdapter(Adapter*);
	RoleManager* getRoleManager();
	void setRoleManager(RoleManager*);
	void clearPolicy();
	vector<string> getAllSubjects();
	vector<string> getAllNamedSubjects(string);
	vector<string> getAllObjects();
	vector<string> getAllNamedObjects(string);
	vector<string> getAllActions();
	vector<string> getAllNamedActions(string);
	vector<string> getAllRoles();
	vector<string> getAllNamedRoles(string);
	vector<string> getPolicy();
	vector<string> getFilteredPolicy(int, string);
	vector<string> getNamedPolicy(string);
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
	bool addFunction(function<bool (string, string)>);
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