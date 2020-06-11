#pragma once

#include "pch.h"

#include "./group_role_manager.h"
#include "../exception/CasbinRBACException.h"

/**
 * GroupRoleManager is the constructor for creating an instance of the
 * GroupRoleManager implementation.
 *
 * @param max_hierarchy_level the maximized allowed RBAC hierarchy level.
 */
GroupRoleManager* GroupRoleManager :: NewGroupRoleManager(int max_hierarchy_level){
    return (GroupRoleManager*)NewRoleManager(max_hierarchy_level);
}

/**
 * hasLink determines whether role: name1 inherits role: name2.
 * domain is a prefix to the roles.
 */
bool GroupRoleManager :: HasLink(string name1, string name2, vector<string> domain) {
    if (DefaultRoleManager :: HasLink(name1, name2, domain)) {
        return true;
    }
    unsigned int domain_length = sizeof(domain) / sizeof(domain[0]);
    // check name1's groups
    if (domain_length == 1) {
        try {
            vector<string> domain1;
            vector<string> groups = DefaultRoleManager :: GetRoles(name1, domain1);
            for (vector<string> :: iterator group = groups.begin() ; group < groups.end() ; group++) {
                if (DefaultRoleManager :: HasLink(*group, name2, domain)) {
                    return true;
                }
            }
        } catch (CasbinRBACException ignore) {
            return false;
        }
    }
    return false;
}