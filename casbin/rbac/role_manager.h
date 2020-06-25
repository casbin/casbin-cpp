#ifndef CASBIN_CPP_RBAC_ROLE_MANAGER
#define CASBIN_CPP_RBAC_ROLE_MANAGER

#include <string>
#include <vector>

using namespace std;

// RoleManager provides interface to define the operations for managing roles.
class RoleManager {
    public:
    // Clear clears all stored data and resets the role manager to the initial state.
    virtual void Clear() = 0;
    // AddLink adds the inheritance link between two roles. role: name1 and role: name2.
    // domain is a prefix to the roles (can be used for other purposes).
    virtual void AddLink(string name1, string name2, vector<string> domain = vector<string>{}) = 0;
    // DeleteLink deletes the inheritance link between two roles. role: name1 and role: name2.
    // domain is a prefix to the roles (can be used for other purposes).
    virtual void DeleteLink(string name1, string name2, vector<string> domain = vector<string>{}) = 0;
    // HasLink determines whether a link exists between two roles. role: name1 inherits role: name2.
    // domain is a prefix to the roles (can be used for other purposes).
    virtual bool HasLink(string name1, string name2, vector<string> domain = vector<string>{}) = 0;
    // GetRoles gets the roles that a user inherits.
    // domain is a prefix to the roles (can be used for other purposes).
    virtual vector<string> GetRoles(string name, vector<string> domain = vector<string>{}) = 0;
    // GetUsers gets the users that inherits a role.
    // domain is a prefix to the users (can be used for other purposes).
    virtual vector<string> GetUsers(string name, vector<string> domain = vector<string>{}) = 0;
    // PrintRoles prints all the roles to log.
    virtual void PrintRoles() = 0;
};

#endif