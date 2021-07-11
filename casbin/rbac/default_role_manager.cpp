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

#ifndef DEFAULT_ROLE_MANAGER_CPP
#define DEFAULT_ROLE_MANAGER_CPP


#include "./default_role_manager.h"
#include "../exception/casbin_rbac_exception.h"

namespace casbin {

Role* Role::NewRole(const std::string& name) {
    Role* role = new Role;
    role->name = name;
    return role;
}

void Role::AddRole(Role* role) {
    for (auto role_it : this->roles) {
        if (role_it->name == role->name)
            return;
    }

    this->roles.push_back(role);
}

void Role::DeleteRole(Role* role) {
    for (auto it = roles.begin(); it != roles.end(); ++it) {
        if ((*it)->name == role->name)
            roles.erase(it);
    }
}

bool Role::HasRole(const std::string& name, int hierarchy_level) {
    if (this->name == name)
        return true;

    if (hierarchy_level <= 0)
        return false;

    for(auto role : roles) {
        if (role->HasRole(name, hierarchy_level - 1))
            return true;
    }

    return false;
}

bool Role::HasDirectRole(const std::string& name) {
    for(auto role_it : roles) {
        if (role_it->name == name)
            return true;
    }

    return false;
}

std::string Role::ToString() {
    if(this->roles.size()==0)
        return "";

    std::string names = "";
    if(this->roles.size() != 1)
        names += "(";

    bool flag = true;
    for (auto role : this->roles) {
        if (flag)
            names += role->name, flag = false;
        else
            names += ", " + role->name;
    }

    if(this->roles.size() != 1)
        names += ")";

    return this->name + " < " + names;
}

std::vector<std::string> Role::GetRoles() {
    std::vector<std::string> names;
    for(int i = 0 ; i < roles.size() ; i++)
        names.push_back(roles[i]->name);

    return names;
}

bool DefaultRoleManager::HasRole(const std::string& name) {
    bool ok = false;
    if (this->has_pattern) {
        for (auto [first, _] : all_roles) {
            if (this->matching_func(name, first))
                ok = true;
        }
    }
    else
        ok = this->all_roles.find(name) != this->all_roles.end();

    return ok;
}

Role* DefaultRoleManager::CreateRole(const std::string& name) {
    Role* role;
    bool ok = this->all_roles.find(name) != this->all_roles.end();
    if (!ok) {
        all_roles[name] = Role::NewRole(name);
        role = all_roles[name];
    } else
        role = all_roles[name];

    if (this->has_pattern) {
        for (auto [first, _] : this->all_roles) {
            if (this->matching_func(name, first) && name!=first) {
                Role* role1;
                bool ok1 = this->all_roles.find(first) != this->all_roles.end();
                if (!ok1) {
                    all_roles[first] = Role::NewRole(first);
                    role1 = all_roles[first];
                } else
                    role1 = all_roles[first];
                role->AddRole(role1);
            }
        }
    }

    return role;
}

/**
 * DefaultRoleManager is the constructor for creating an instance of the
 * default RoleManager implementation.
 *
 * @param max_hierarchy_level the maximized allowed RBAC hierarchy level.
 */
DefaultRoleManager::DefaultRoleManager(int max_hierarchy_level) {
    this->max_hierarchy_level = max_hierarchy_level;
    this->has_pattern = false;
}

// e.BuildRoleLinks must be called after AddMatchingFunc().
//
// example: e.GetRoleManager().(*defaultrolemanager.RoleManager).AddMatchingFunc('matcher', util.KeyMatch)
void DefaultRoleManager::AddMatchingFunc(MatchingFunc fn) {
    this->has_pattern = true;
    this->matching_func = fn;
}

/**
 * clear clears all stored data and resets the role manager to the initial state.
 */
void DefaultRoleManager::Clear() {
    this->all_roles.clear();
}

// AddLink adds the inheritance link between role: name1 and role: name2.
// aka role: name1 inherits role: name2.
// domain is a prefix to the roles.
void DefaultRoleManager::AddLink(std::string name1, std::string name2, const std::vector<std::string>& domain) {
    if (domain.size() == 1) {
        name1 = domain[0] + "::" + name1;
        name2 = domain[0] + "::" + name2;
    } else if (domain.size() > 1)
        throw CasbinRBACException("error: domain should be 1 parameter");

    Role* role1 = this->CreateRole(name1);
    Role* role2 = this->CreateRole(name2);
    role1->AddRole(role2);
}

/**
 * deleteLink deletes the inheritance link between role: name1 and role: name2.
 * aka role: name1 does not inherit role: name2 any more.
 * domain is a prefix to the roles.
 */
void DefaultRoleManager::DeleteLink(std::string name1, std::string name2, const std::vector<std::string>& domain) {
    size_t domain_length = domain.size();
    if (domain_length == 1) {
        name1 = domain[0] + "::" + name1;
        name2 = domain[0] + "::" + name2;
    } else if (domain_length > 1)
        throw CasbinRBACException("error: domain should be 1 parameter");

    if (!HasRole(name1) || !HasRole(name2))
        throw CasbinRBACException("error: name1 or name2 does not exist");

    Role* role1 = this->CreateRole(name1);
    Role* role2 = this->CreateRole(name2);
    role1->DeleteRole(role2);
}

/**
 * hasLink determines whether role: name1 inherits role: name2.
 * domain is a prefix to the roles.
 */
bool DefaultRoleManager::HasLink(std::string name1, std::string name2, const std::vector<std::string>& domain) {
    size_t domain_length = domain.size();
    if (domain_length == 1) {
        name1 = domain[0] + "::" + name1;
        name2 = domain[0] + "::" + name2;
    } else if (domain_length > 1)
        throw CasbinRBACException("error: domain should be 1 parameter");

    if (!name1.compare(name2))
        return true;
    if (!HasRole(name1) || !HasRole(name2))
        return false;

    Role* role1 = this->CreateRole(name1);
    return role1->HasRole(name2, max_hierarchy_level);
}

/**
 * getRoles gets the roles that a subject inherits.
 * domain is a prefix to the roles.
 */
std::vector<std::string> DefaultRoleManager::GetRoles(std::string name, const std::vector<std::string>& domain) {
    size_t domain_length = domain.size();
    if (domain_length == 1)
        name = domain[0] + "::" + name;
    else if (domain_length > 1)
        throw CasbinRBACException("error: domain should be 1 parameter");

    if (!HasRole(name)) {
        std::vector<std::string> roles;
        return roles;
    }

    std::vector<std::string> roles = this->CreateRole(name)->GetRoles();
    if (domain_length == 1) {
        for (auto& role : roles)
            role = role.substr(domain[0].length() + 2, role.length() - domain[0].length() - 2);
    }

    return roles;
}

std::vector<std::string> DefaultRoleManager::GetUsers(std::string name, const std::vector<std::string>& domain) {
    size_t domain_length = domain.size();
    if (domain_length == 1)
        name = domain[0] + "::" + name;
    else if (domain_length > 1)
        throw CasbinRBACException("error: domain should be 1 parameter");

    if (!this->HasRole(name))
        throw CasbinRBACException("error: name does not exist");

    std::vector<std::string> names;
    for (auto [_, role] : this->all_roles) {
        if (role->HasDirectRole(name))
            names.push_back(role->name);
    }

    if (domain_length == 1) {
        for (auto& name : names)
            name = name.substr(domain[0].length() + 2, name.length() - domain[0].length() - 2);
    }

    return names;
}

/**
 * printRoles prints all the roles to log.
 */
void DefaultRoleManager::PrintRoles() {
    // DefaultLogger df_logger;
    // df_logger.EnableLog(true);

    // Logger *logger = &df_logger;
    // LogUtil::SetLogger(*logger);

    std::string text = this->all_roles.begin()->second->ToString();
    for (auto [_, role] : this->all_roles)
        text += ", " + role->ToString();
    // LogUtil::LogPrint(text);
}

} // namespace casbin

#endif // DEFAULT_ROLE_MANAGER_CPP
