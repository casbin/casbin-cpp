#ifndef CASBIN_CPP_RBAC_GROUP_ROLE_MANAGER
#define CASBIN_CPP_RBAC_GROUP_ROLE_MANAGER

#include "./default_role_manager.h"

/**
 * GroupRoleManager is used for authorization if the user's group is the role who has permission,
 * but the group information is in the default format (policy start with "g") and the role information
 * is in named format (policy start with "g2", "g3", ...).
 * e.g.
 * p, admin, domain1, data1, read
 * g, alice, group1
 * g2, group1, admin, domain1
 *
 * As for the previous example, alice should have the permission to read data1, but if we use the
 * DefaultRoleManager, it will return false.
 * GroupRoleManager is to handle this situation.
 */
class GroupRoleManager : public DefaultRoleManager {
    public:
        /**
         * GroupRoleManager is the constructor for creating an instance of the
         * GroupRoleManager implementation.
         *
         * @param max_hierarchy_level the maximized allowed RBAC hierarchy level.
         */
        static GroupRoleManager* NewGroupRoleManager(int max_hierarchy_level);

        /**
         * hasLink determines whether role: name1 inherits role: name2.
         * domain is a prefix to the roles.
         */
        bool HasLink(string name1, string name2, vector<string> domain);
};

#endif