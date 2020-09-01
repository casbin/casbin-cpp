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

#ifndef CASBIN_CPP_RBAC_DEFAULT_ROLE_MANAGER
#define CASBIN_CPP_RBAC_DEFAULT_ROLE_MANAGER

#include <unordered_map>

#include "./role_manager.h"

using namespace std;

typedef bool (*MatchingFunc)(string, string);

/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
    
    private:
        vector <Role*> roles;

    public:
        string name;

        static Role* NewRole(string name);
        
        void AddRole(Role* role);

        void DeleteRole(Role* role);

        bool HasRole(string name, int hierarchy_level);

        bool HasDirectRole(string name);

        string ToString();

        vector<string> GetRoles();
};

class DefaultRoleManager : public RoleManager {
    private:
        unordered_map <string, Role*> all_roles;
        bool has_pattern;
        int max_hierarchy_level;
        MatchingFunc matching_func;

        bool HasRole(string name);

        Role* CreateRole(string name);

    public:

        /**
         * DefaultRoleManager is the constructor for creating an instance of the
         * default RoleManager implementation.
         *
         * @param max_hierarchy_level the maximized allowed RBAC hierarchy level.
         */
        DefaultRoleManager(int max_hierarchy_level);

        // e.BuildRoleLinks must be called after AddMatchingFunc().
        //
        // example: e.GetRoleManager().(*defaultrolemanager.RoleManager).AddMatchingFunc('matcher', util.KeyMatch)
        void AddMatchingFunc(MatchingFunc fn);

        /**
         * clear clears all stored data and resets the role manager to the initial state.
         */
        void Clear();

        // AddLink adds the inheritance link between role: name1 and role: name2.
        // aka role: name1 inherits role: name2.
        // domain is a prefix to the roles.
        void AddLink(string name1, string name2, vector<string> domain = {});

        /**
         * deleteLink deletes the inheritance link between role: name1 and role: name2.
         * aka role: name1 does not inherit role: name2 any more.
         * domain is a prefix to the roles.
         */
        void DeleteLink(string name1, string name2, vector<string> domain = {});

        /**
         * hasLink determines whether role: name1 inherits role: name2.
         * domain is a prefix to the roles.
         */
        bool HasLink(string name1, string name2, vector<string> domain = {});

        /**
         * getRoles gets the roles that a subject inherits.
         * domain is a prefix to the roles.
         */
        vector <string> GetRoles(string name, vector<string> domain = {});

        vector<string> GetUsers(string name, vector<string> domain = {});

        /**
         * printRoles prints all the roles to log.
         */
        void PrintRoles();
};

#endif