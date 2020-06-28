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

#include "pch.h"

#include "./enforcer.h"

// GetUsersForRoleInDomain gets the users that has a role inside a domain. Add by Gordon
vector<string> Enforcer :: GetUsersForRoleInDomain(string name, string domain) {
    vector<string> domains{domain};
	vector<string> res = this->model->m["g"].assertion_map["g"]->rm->GetUsers(name, domains);
	return res;
}

// GetRolesForUserInDomain gets the roles that a user has inside a domain.
vector<string> Enforcer :: GetRolesForUserInDomain(string name, string domain) {
    vector<string> domains{domain};
	vector<string> res = this->model->m["g"].assertion_map["g"]->rm->GetRoles(name, domains);
	return res;
}

// GetPermissionsForUserInDomain gets permissions for a user or role inside a domain.
vector<vector<string>> Enforcer :: GetPermissionsForUserInDomain(string user, string domain) {
    vector<string> field_values{user, domain};
	return this->GetFilteredPolicy(0, field_values);
}

// AddRoleForUserInDomain adds a role for a user inside a domain.
// Returns false if the user already has the role (aka not affected).
bool Enforcer :: AddRoleForUserInDomain(string user, string role, string domain) {
    vector<string> params{user, role, domain};
	return this->AddGroupingPolicy(params);
}

// DeleteRoleForUserInDomain deletes a role for a user inside a domain.
// Returns false if the user does not have the role (aka not affected).
bool Enforcer :: DeleteRoleForUserInDomain(string user, string role, string domain) {
    vector<string> params{user, role, domain};
	return this->RemoveGroupingPolicy(params);
}