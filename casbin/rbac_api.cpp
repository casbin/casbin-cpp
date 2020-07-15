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
#include "./exception/casbin_enforcer_exception.h"
#include "./util/util.h"

// GetRolesForUser gets the roles that a user has.
vector<string> Enforcer :: GetRolesForUser(string name, vector<string> domain) {
    vector<string> res = this->model->m["g"].assertion_map["g"]->rm->GetRoles(name, domain);
    return res;
}

// GetUsersForRole gets the users that has a role.
vector<string> Enforcer :: GetUsersForRole(string name, vector<string> domain) {
    vector<string> res = this->model->m["g"].assertion_map["g"]->rm->GetUsers(name, domain);
    return res;
}

// HasRoleForUser determines whether a user has a role.
bool Enforcer :: HasRoleForUser(string name, string role) {
    vector<string> domain;
    vector<string> roles = this->GetRolesForUser(name, domain);

    bool has_role = false;
    for (int i = 0 ; i < roles.size() ; i++) {
        if (roles[i] == role) {
            has_role = true;
            break;
        }
    }

    return has_role;
}

// AddRoleForUser adds a role for a user.
// Returns false if the user already has the role (aka not affected).
bool Enforcer :: AddRoleForUser(string user, string role) {
    vector<string> params{user, role};
    return this->AddGroupingPolicy(params);
}

// AddRolesForUser adds roles for a user.
// Returns false if the user already has the roles (aka not affected).
bool Enforcer :: AddRolesForUser(string user, vector<string> roles) {
    bool f = false;
    for(int i=0;i<roles.size();i++) {
        bool b = this->AddGroupingPolicy({user, roles[i]});
        if(b)
            f = true;
    }
    return f;
}

// DeleteRoleForUser deletes a role for a user.
// Returns false if the user does not have the role (aka not affected).
bool Enforcer :: DeleteRoleForUser(string user, string role) {
    vector<string> params{user, role};
    return this->RemoveGroupingPolicy(params);
}

// DeleteRolesForUser deletes all roles for a user.
// Returns false if the user does not have any roles (aka not affected).
bool Enforcer :: DeleteRolesForUser(string user) {
    vector<string> field_values{user};
    return this->RemoveFilteredGroupingPolicy(0, field_values);
}

// DeleteUser deletes a user.
// Returns false if the user does not exist (aka not affected).
bool Enforcer :: DeleteUser(string user) {
    vector<string> field_values{user};

    bool res1 = this->RemoveFilteredGroupingPolicy(0, field_values);

    bool res2 = this->RemoveFilteredPolicy(0, field_values);

    return res1 || res2;
}

// DeleteRole deletes a role.
// Returns false if the role does not exist (aka not affected).
bool Enforcer :: DeleteRole(string role) {
    vector<string> field_values{role};

    bool res1 = this->RemoveFilteredGroupingPolicy(1, field_values);

    bool res2 = this->RemoveFilteredPolicy(0, field_values);

    return res1 || res2;
}

// DeletePermission deletes a permission.
// Returns false if the permission does not exist (aka not affected).
bool Enforcer :: DeletePermission(vector<string> permission) {
    vector<string> field_values{permission};
    return this->RemoveFilteredPolicy(1, field_values);
}

// AddPermissionForUser adds a permission for a user or role.
// Returns false if the user or role already has the permission (aka not affected).
bool Enforcer :: AddPermissionForUser(string user, vector<string> permission) {
    return this->AddPolicy(JoinSlice(user, permission));
}

// DeletePermissionForUser deletes a permission for a user or role.
// Returns false if the user or role does not have the permission (aka not affected).
bool Enforcer :: DeletePermissionForUser(string user, vector<string> permission) {
    return this->RemovePolicy(JoinSlice(user, permission));
}

// DeletePermissionsForUser deletes permissions for a user or role.
// Returns false if the user or role does not have any permissions (aka not affected).
bool Enforcer :: DeletePermissionsForUser(string user) {
    vector<string> field_values{user};
    return this->RemoveFilteredPolicy(0, field_values);
}

// GetPermissionsForUser gets permissions for a user or role.
vector<vector<string>> Enforcer :: GetPermissionsForUser(string user) {
    vector<string> field_values{user};
    return this->GetFilteredPolicy(0, field_values);
}

// HasPermissionForUser determines whether a user has a permission.
bool Enforcer :: HasPermissionForUser(string user, vector<string> permission) {
    return this->HasPolicy(JoinSlice(user, permission));
}

// GetImplicitRolesForUser gets implicit roles that a user has.
// Compared to GetRolesForUser(), this function retrieves indirect roles besides direct roles.
// For example:
// g, alice, role:admin
// g, role:admin, role:user
//
// GetRolesForUser("alice") can only get: ["role:admin"].
// But GetImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
vector<string> Enforcer :: GetImplicitRolesForUser(string name, vector<string> domain) {
    vector<string> res;
    unordered_map<string, bool> role_set;
    role_set[name] = true;

    vector<string> q;
    q.push_back(name);

    while (q.size() > 0) {
        string name = q[0];
        q.erase(q.begin());

        vector<string> roles = this->rm->GetRoles(name, domain);

        for (int i = 0 ; i < roles.size() ; i++) {
            if (!(role_set.find(roles[i]) != role_set.end())) {
                res.push_back(roles[i]);
                q.push_back(roles[i]);
                role_set[roles[i]] = true;
            }
        }
    }

    return res;
}

// GetImplicitPermissionsForUser gets implicit permissions for a user or role.
// Compared to GetPermissionsForUser(), this function retrieves permissions for inherited roles.
// For example:
// p, admin, data1, read
// p, alice, data2, read
// g, alice, admin
//
// GetPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
// But GetImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
vector<vector<string>> Enforcer :: GetImplicitPermissionsForUser(string user, vector<string> domain) {
    vector<string> roles = this->GetImplicitRolesForUser(user, domain);
    roles.insert(roles.begin(), user);

    bool with_domain = false;
    if (domain.size() == 1)
        with_domain = true;
    else if (domain.size() > 1)
        throw CasbinEnforcerException("Domain should be 1 parameter");

    vector<vector<string>> res;
    vector<vector<string>> permissions;

    for (int i = 0 ; i < roles.size() ; i++) {
        if (with_domain)
            permissions = this->GetPermissionsForUserInDomain(roles[i], domain[0]);
        else
            permissions = this->GetPermissionsForUser(roles[i]);

        for (int i = 0 ; i < permissions.size() ; i++)
            res.push_back(permissions[i]);
    }

    return res;
}

// GetImplicitUsersForPermission gets implicit users for a permission.
// For example:
// p, admin, data1, read
// p, bob, data1, read
// g, alice, admin
//
// GetImplicitUsersForPermission("data1", "read") will get: ["alice", "bob"].
// Note: only users will be returned, roles (2nd arg in "g") will be excluded.
vector<string> Enforcer :: GetImplicitUsersForPermission(vector<string> permission) {
    vector<string> p_subjects = this->GetAllSubjects();
    vector<string> g_inherit = this->model->GetValuesForFieldInPolicyAllTypes("g", 1);
    vector<string> g_subjects = this->model->GetValuesForFieldInPolicyAllTypes("g", 0);

    vector<string> subjects(p_subjects);
    subjects.insert(subjects.end(), g_subjects.begin(), g_subjects.end());
    ArrayRemoveDuplicates(subjects);

    vector<string> res;
    for(int i=0;i<subjects.size();i++) {
        bool allowed = this->Enforce({subjects[i], permission[0], permission[1]});

        if(allowed) {
            res.push_back(subjects[i]);
        }
    }

    res = SetSubtract(res, g_inherit);
    return res;
}