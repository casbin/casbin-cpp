#ifndef CASBIN_CPP_RBAC_DEFAULT_ROLE_MANAGER
#define CASBIN_CPP_RBAC_DEFAULT_ROLE_MANAGER

#include <unordered_map>

#include "RoleManager.h"
#include "../exception/CasbinRBACException.h"
#include "../log/LogUtil.h"

typedef bool (*MatchingFunc)(string, string);

/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
    
    private:
        vector <Role*> roles;

    public:
        string name;

        static Role* newRole(string name) {
            Role* role;
            role->name = name;
            return role;
        }
        
        void addRole(Role* role) {
            for(int i = 0 ; i < this->roles.size() ; i++){
                if(this->roles[i]->name == role->name)
                    return;
            }

            this->roles.push_back(role);
        }

        void deleteRole(Role* role) {
            for (vector <Role*> :: iterator it = roles.begin() ; it != roles.end() ; it++) {
                if (!(*it)->name.compare(role->name)) {
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

            for (vector <Role*> :: iterator it = roles.begin() ; it != roles.end() ; it++) {
                if ((*it)->hasRole(name, hierarchyLevel - 1)) {
                    return true;
                }
            }
            return false;
        }

        bool hasDirectRole(string name) {
            for (vector <Role*> :: iterator it = roles.begin() ; it != roles.end() ; it++) {
                if (!(*it)->name.compare(name)) {
                    return true;
                }
            }

            return false;
        }

        string toString() {
            string names = "";
            for (int i = 0; i < roles.size(); i ++) {
                Role* role = roles[i];
                if (i == 0) {
                    names.append(role->name);
                } else {
                    names.append(", " + role->name);
                }
            }
            return name + " < " + names;
        }

        vector<string> getRoles() {
            vector <string> names;
            for (vector <Role*> :: iterator it = roles.begin() ; it != roles.end() ; it++) {
                names.push_back((*it)->name);
            }
            return names;
        }
};

class DefaultRoleManager : public RoleManager {
    private:
        unordered_map <string, Role*> allRoles;
        bool hasPattern;
        int maxHierarchyLevel;
        MatchingFunc matchingFunc;

        bool hasRole(string name) {
            bool ok = false;
            if(this->hasPattern) {
                for(unordered_map <string, Role*> :: iterator it = this->allRoles.begin() ; it != this->allRoles.end() ; it++){
                    if(this->matchingFunc(name, it->first))
                        ok = true;
                }
            } else {
                ok = this->allRoles.find(name) != this->allRoles.end();
            }

            return ok;
        }

        Role* createRole(string name) {
            Role* role;
            bool ok = this->allRoles.find(name) != this->allRoles.end();
            if(!ok){
                allRoles[name] = Role :: newRole(name);
                role = allRoles[name];
            } else
                role = allRoles[name];

            if(this->hasPattern) {
                for(unordered_map <string, Role*> :: iterator it = this->allRoles.begin() ; it != this->allRoles.end() ; it++){
                    if(this->matchingFunc(name, it->first) && name!=it->first) {
                        Role* role1;
                        bool ok1 = this->allRoles.find(it->first) != this->allRoles.end();
                        if(!ok){
                            allRoles[it->first] = Role :: newRole(it->first);
                            role1 = allRoles[it->first];
                        } else
                            role1 = allRoles[it->first];
                        role->addRole(role1);
                    }
                }
            }

            return role;
        }

    public:

        /**
         * DefaultRoleManager is the constructor for creating an instance of the
         * default RoleManager implementation.
         *
         * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
         */
        static DefaultRoleManager* NewRoleManager(int maxHierarchyLevel) {
            DefaultRoleManager* rm;
            rm->maxHierarchyLevel = maxHierarchyLevel;
            rm->hasPattern = false;
            return rm;
        }

        // e.BuildRoleLinks must be called after AddMatchingFunc().
        //
        // example: e.GetRoleManager().(*defaultrolemanager.RoleManager).AddMatchingFunc('matcher', util.KeyMatch)
        void AddMatchingFunc(string name, MatchingFunc fn) {
            this->hasPattern = true;
            this->matchingFunc = fn;
        }
        

        /**
         * clear clears all stored data and resets the role manager to the initial state.
         */
        void Clear() {
            this->allRoles.clear();
        }

        // AddLink adds the inheritance link between role: name1 and role: name2.
        // aka role: name1 inherits role: name2.
        // domain is a prefix to the roles.
        void AddLink(string name1, string name2, vector<string> domain) {
            if(domain.size() == 1) {
                name1 = domain[0] + "::" + name1;
                name2 = domain[0] + "::" + name2;
            } else if(domain.size() > 1) {
                throw CasbinRBACException("error: domain should be 1 parameter");
            }

            Role* role1 = this->createRole(name1);
            Role* role2 = this->createRole(name2);
            role1->addRole(role2);
        }

        /**
         * deleteLink deletes the inheritance link between role: name1 and role: name2.
         * aka role: name1 does not inherit role: name2 any more.
         * domain is a prefix to the roles.
         */
        void DeleteLink(string name1, string name2, vector <string> domain) {
            unsigned int domain_length = domain.size();
            if (domain_length == 1) {
                name1 = domain[0] + "::" + name1;
                name2 = domain[0] + "::" + name2;
            } else if (domain_length > 1) {
                throw CasbinRBACException("error: domain should be 1 parameter");
            }

            if (!hasRole(name1) || !hasRole(name2)) {
                throw CasbinRBACException("error: name1 or name2 does not exist");
            }

            Role* role1 = this->createRole(name1);
            Role* role2 = this->createRole(name2);
            role1->deleteRole(role2);
        }

        /**
         * hasLink determines whether role: name1 inherits role: name2.
         * domain is a prefix to the roles.
         */
        bool HasLink(string name1, string name2, vector <string> domain) {
            unsigned int domain_length = domain.size();
            if (domain_length == 1) {
                name1 = domain[0] + "::" + name1;
                name2 = domain[0] + "::" + name2;
            } else if (domain_length > 1) {
                throw CasbinRBACException("error: domain should be 1 parameter");
            }

            if (!name1.compare(name2)) {
                return true;
            }

            if (!hasRole(name1) || !hasRole(name2)) {
                return false;
            }

            Role* role1 = this->createRole(name1);
            return role1->hasRole(name2, maxHierarchyLevel);
        }

        /**
         * getRoles gets the roles that a subject inherits.
         * domain is a prefix to the roles.
         */
        vector <string> GetRoles(string name, vector <string> domain) {
            unsigned int domain_length = domain.size();
            if (domain_length == 1) {
                name = domain[0] + "::" + name;
            } else if (domain_length > 1) {
                throw CasbinRBACException("error: domain should be 1 parameter");
            }

            if (!hasRole(name)) {
                vector<string> roles;
                return roles;
            }

            vector <string> roles = this->createRole(name)->getRoles();
            if (domain_length == 1) {
                for (int i = 0; i < roles.size(); i ++) {
                    roles[i] = roles[i].substr(domain[0].length() + 2, roles[i].length() - domain[0].length() - 2);
                }
            }
            return roles;
        }

        vector<string> GetUsers(string name, vector<string> domain) {
            if(domain.size() == 1)
                name = domain[0] + "::" + name;
            else if(domain.size() > 1)
                throw CasbinRBACException("error: domain should be 1 parameter");

            if(this->hasRole(name))
                throw CasbinRBACException("error: name does not exist");

            vector<string> names;
            for(unordered_map <string, Role*> :: iterator it = this->allRoles.begin() ; it != this->allRoles.end() ; it++){
                Role* role = it->second;
                if(role->hasDirectRole(name))
                    names.push_back(role->name);
            }

            if(domain.size() == 1) {
                for(int i = 0 ; i < names.size() ; i++)
                    names[i] = names[i].substr(domain[0].length() + 2, names[i].length() - domain[0].length() - 2);
            }
            return names;
        }

        /**
         * printRoles prints all the roles to log.
         */
        void PrintRoles() {
            DefaultLogger df_logger;
            df_logger.EnableLog(true);

            Logger *logger = &df_logger;
            LogUtil::SetLogger(*logger);

            string text = this->allRoles.begin()->second->toString();
            unordered_map <string, Role*> :: iterator it = this->allRoles.begin();
            it++;
            for ( ; it != this->allRoles.end() ; it++) {
                text += ", " + it->second->toString();
            }
            LogUtil::LogPrint(text);
        }
};

#endif