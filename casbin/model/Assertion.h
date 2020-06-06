#ifndef CASBIN_CPP_MODEL_ASSERTION
#define CASBIN_CPP_MODEL_ASSERTION

#include <algorithm>

#include "../rbac/role_manager.h"
// #include "../log/LogUtil.h"
#include "../exception/IllegalArgumentException.h"

using namespace std;

enum policy_op{
    policy_add,
    policy_remove
};

// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act
class Assertion {
    public:

        string key;
        string value;
        vector<string> tokens;
        vector<vector<string>> policy;
        RoleManager *rm;

        void BuildIncrementalRoleLinks(RoleManager* rm, policy_op op, vector<vector<string>> rules) {
            this->rm = rm;
            int char_count = count(this->value.begin(), this->value.end(), '_');

            if (char_count < 2)
                throw new IllegalArgumentException("the number of \"_\" in role definition should be at least 2");

            for (vector<vector<string>> :: iterator it = this->policy.begin() ; it != this->policy.end() ; it++) {
                vector<string> rule = *it;

                if (rule.size() < char_count)
                    throw new IllegalArgumentException("grouping policy elements do not meet role definition");
                if (rule.size() > char_count)
                    rule = vector<string>(rule.begin(), rule.begin() + char_count);

                vector<string> domain(rule.begin() + 2, rule.end());

                switch(op) {
                    case policy_op :: policy_add:
                        this->rm->AddLink(rule[0], rule[1], domain);
                    case policy_op :: policy_remove:
                        this->rm->DeleteLink(rule[0], rule[1], domain);
                }
            }
        }

        void BuildRoleLinks(RoleManager* rm) {
            this->rm = rm;
            int char_count = count(this->value.begin(), this->value.end(), '_');

            if (char_count < 2)
                throw new IllegalArgumentException("the number of \"_\" in role definition should be at least 2");

            for (vector<vector<string>> :: iterator it = this->policy.begin() ; it != this->policy.end() ; it++) {
                vector<string> rule = *it;

                if (rule.size() < char_count)
                    throw new IllegalArgumentException("grouping policy elements do not meet role definition");
                if (rule.size() > char_count)
                    rule = vector<string>(rule.begin(), rule.begin() + char_count);

                vector<string> domain(rule.begin() + 2, rule.end());
                this->rm->AddLink(rule[0], rule[1], domain);
            }

            // DefaultLogger df_logger;
            // df_logger.EnableLog(true);

            // Logger *logger = &df_logger;
            // LogUtil :: SetLogger(*logger);

            // LogUtil :: LogPrint("Role links for: " + Key);

            this->rm->PrintRoles();
        }
};

#endif