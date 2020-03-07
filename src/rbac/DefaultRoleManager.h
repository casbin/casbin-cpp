#include <unordered_map>

#include "RoleManager.h"
#include "../exception/IllegalArgumentException.h"
#include "../log/LogUtil.h"

/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
    
    private:
        vector <Role> roles;

    public:
        string name;

        Role(string name) {
            this->name = name;
        }

        void addRole(Role role) {
            for (Role r : roles) {
                if (!r.name.compare(role.name)) {
                    return;
                }
            }

            roles.push_back(role);
        }

        void deleteRole(Role role) {
            for (vector <Role> :: iterator it = roles.begin() ; it != roles.end() ; it++) {
                if (!(*it).name.compare(role.name)) {
                    roles.erase(it);
                }
            }
        }

        bool hasRole(string name, int hierarchyLevel) {
            if (!this->name.compare(name)) {
                return true;
            }

            if (hierarchyLevel <= 0) {
                return false;
            }

            for (vector <Role> :: iterator it = roles.begin() ; it != roles.end() ; it++) {
                if ((*it).hasRole(name, hierarchyLevel - 1)) {
                    return true;
                }
            }
            return false;
        }

        bool hasDirectRole(string name) {
            for (vector <Role> :: iterator it = roles.begin() ; it != roles.end() ; it++) {
                if (!(*it).name.compare(name)) {
                    return true;
                }
            }

            return false;
        }

        string toString() {
            string names = "";
            for (int i = 0; i < roles.size(); i ++) {
                Role role = roles[i];
                if (i == 0) {
                    names.append(role.name);
                } else {
                    names.append(", " + role.name);
                }
            }
            return name + " < " + names;
        }

        vector<string> getRoles() {
            vector <string> names;
            for (vector <Role> :: iterator it = roles.begin() ; it != roles.end() ; it++) {
                names.push_back((*it).name);
            }
            return names;
        }
};

class DefaultRoleManager : public RoleManager {
    private:
        unordered_map <string, Role> allRoles;
        int maxHierarchyLevel;

        bool hasRole(string name) {
            return allRoles.find(name) != allRoles.end();
        }

        Role createRole(string name) {
            if (hasRole(name)) {
                return allRoles.at(name);
            } else {
                Role role = Role(name);
                allRoles[name] = role;
                return role;
            }
        }

    public:
        /**
         * DefaultRoleManager is the constructor for creating an instance of the
         * default RoleManager implementation.
         *
         * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
         */
        DefaultRoleManager(int maxHierarchyLevel) {
            this->maxHierarchyLevel = maxHierarchyLevel;
        }

        

        /**
         * clear clears all stored data and resets the role manager to the initial state.
         */
        void clear() {
            allRoles.clear();
        }

        /**
         * addLink adds the inheritance link between role: name1 and role: name2.
         * aka role: name1 inherits role: name2.
         * domain is a prefix to the roles.
         */
        void addLink(string name1, string name2, vector <string> domain) {
            unsigned int domain_length = domain.size();
            if (domain_length == 1) {
                name1 = domain[0] + "::" + name1;
                name2 = domain[0] + "::" + name2;
            } else if (domain_length > 1) {
                throw new IllegalArgumentException("error: domain should be 1 parameter");
            }

            Role role1 = createRole(name1);
            Role role2 = createRole(name2);
            role1.addRole(role2);
        }

        /**
         * deleteLink deletes the inheritance link between role: name1 and role: name2.
         * aka role: name1 does not inherit role: name2 any more.
         * domain is a prefix to the roles.
         */
        void deleteLink(string name1, string name2, vector <string> domain) {
            unsigned int domain_length = domain.size();
            if (domain_length == 1) {
                name1 = domain[0] + "::" + name1;
                name2 = domain[0] + "::" + name2;
            } else if (domain_length > 1) {
                throw new IllegalArgumentException("error: domain should be 1 parameter");
            }

            if (!hasRole(name1) || !hasRole(name2)) {
                throw new IllegalArgumentException("error: name1 or name2 does not exist");
            }

            Role role1 = createRole(name1);
            Role role2 = createRole(name2);
            role1.deleteRole(role2);
        }

        /**
         * hasLink determines whether role: name1 inherits role: name2.
         * domain is a prefix to the roles.
         */
        bool hasLink(string name1, string name2, vector <string> domain) {
            unsigned int domain_length = domain.size();
            if (domain_length == 1) {
                name1 = domain[0] + "::" + name1;
                name2 = domain[0] + "::" + name2;
            } else if (domain_length > 1) {
                throw new IllegalArgumentException("error: domain should be 1 parameter");
            }

            if (!name1.compare(name2)) {
                return true;
            }

            if (!hasRole(name1) || !hasRole(name2)) {
                return false;
            }

            Role role1 = createRole(name1);
            return role1.hasRole(name2, maxHierarchyLevel);
        }

        /**
         * getRoles gets the roles that a subject inherits.
         * domain is a prefix to the roles.
         */
        vector <string> getRoles(string name, vector <string> domain) {
            unsigned int domain_length = domain.size();
            if (domain_length == 1) {
                name = domain[0] + "::" + name;
            } else if (domain_length > 1) {
                throw new IllegalArgumentException("error: domain should be 1 parameter");
            }

            if (!hasRole(name)) {
                throw new IllegalArgumentException("error: name does not exist");
            }
            vector <string> roles = createRole(name).getRoles();
            if (domain_length == 1) {
                for (int i = 0; i < roles.size(); i ++) {
                    roles[i] = roles[i].substr(domain[0].length() + 2, roles[i].length());
                }
            }
            return roles;
        }

        /**
         * getUsers gets the users that inherits a subject.
         * domain is an unreferenced parameter here, may be used in other implementations.
         */
        vector <string> getUsers(string name) {
            if (!hasRole(name)) {
                throw new IllegalArgumentException("error: name does not exist");
            }

            vector <string> names;
            for (unordered_map <string, Role> :: iterator it = allRoles.begin() ; it != allRoles.end() ; it++) {
                if ((it->second).hasDirectRole(name)) {
                    names.push_back((it->second).name);
                }
            }
            return names;
        }

        /**
         * printRoles prints all the roles to log.
         */
        void printRoles() {
            DefaultLogger df_logger;
            df_logger.EnableLog(true);

            Logger *logger = &df_logger;
            LogUtil::SetLogger(*logger);

            for (unordered_map <string, Role> :: iterator it = allRoles.begin() ; it != allRoles.end() ; it++) {
                LogUtil::LogPrint((it->second).toString());
            }
        }
};


