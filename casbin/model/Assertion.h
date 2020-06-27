#ifndef CASBIN_CPP_MODEL_ASSERTION
#define CASBIN_CPP_MODEL_ASSERTION

#include "../rbac/role_manager.h"

enum policy_op{
    policy_add,
    policy_remove
};
typedef enum policy_op policy_op;

// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act
class Assertion {
    public:

        string key;
        string value;
        vector<string> tokens;
        vector<vector<string>> policy;
        RoleManager* rm;

        void BuildIncrementalRoleLinks(RoleManager* rm, policy_op op, vector<vector<string>> rules);

        void BuildRoleLinks(RoleManager* rm);
};

#endif