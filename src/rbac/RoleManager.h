#ifndef CASBIN_CPP_RBAC_ROLE_MANAGER
#define CASBIN_CPP_RBAC_ROLE_MANAGER

#include <string>
#include <vector>

#endif

using namespace std;

class RoleManager {
    public:
        /**
         * Clear clears all stored data and resets the role manager to the initial state.
         */
        virtual void clear() = 0;

        /**
         * addLink adds the inheritance link between two roles. role: name1 and role: name2.
         * domain is a prefix to the roles.
         *
         * @param name1 the first role (or user).
         * @param name2 the second role.
         * @param domain the domain the roles belong to.
         */
        virtual void addLink(string name1, string name2, vector <string> domain) = 0;

        /**
         * deleteLink deletes the inheritance link between two roles. role: name1 and role: name2.
         * domain is a prefix to the roles.
         *
         * @param name1 the first role (or user).
         * @param name2 the second role.
         * @param domain the domain the roles belong to.
         */
        virtual void deleteLink(string name1, string name2, vector <string> domain) = 0;

        /**
         * hasLink determines whether a link exists between two roles. role: name1 inherits role: name2.
         * domain is a prefix to the roles.
         *
         * @param name1 the first role (or a user).
         * @param name2 the second role.
         * @param domain the domain the roles belong to.
         * @return whether name1 inherits name2 (name1 has role name2).
         */
        virtual bool hasLink(string name1, string name2, vector <string> domain) = 0;

        /**
         * getRoles gets the roles that a user inherits.
         * domain is a prefix to the roles.
         *
         * @param name the user (or a role).
         * @param domain the domain the roles belong to.
         * @return the roles.
         */
        virtual vector<string> getRoles(string name, vector <string> domain) = 0;

        /**
         * getUsers gets the users that inherits a role.
         * @param name the role.
         * @return the users.
         */
        virtual vector<string> getUsers(string name) = 0;

        /**
         * printRoles prints all the roles to log.
         */
        virtual void printRoles() = 0;
};
