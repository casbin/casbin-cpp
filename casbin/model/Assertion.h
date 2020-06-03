#ifndef CASBIN_CPP_MODEL_ASSERTION
#define CASBIN_CPP_MODEL_ASSERTION

#include <algorithm>

#include "../rbac/role_manager.h"
// #include "../log/LogUtil.h"
#include "../exception/IllegalArgumentException.h"

using namespace std;

// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act
class Assertion {

    public:
        string key;
        string value;
        vector <string> tokens;
        vector <vector<string>> policy;
        RoleManager *rm;

        void BuildRoleLinks(RoleManager* rm) {
            this->rm = rm;
            unsigned int char_count = count(this->value.begin(), this->value.end(), '_');
            for(vector<vector<string>> :: iterator it = this->policy.begin() ; it != this->policy.end() ; it++){

                vector <string> rule = *it;
                if (char_count < 2) {
                    throw new IllegalArgumentException("the number of \"_\" in role definition should be at least 2");
                }
                if (rule.size() < char_count) {
                    throw new IllegalArgumentException("grouping policy elements do not meet role definition");
                }

                if (char_count == 2) {
                    vector<string> domain;
                    this->rm->AddLink(rule[0], rule[1], domain);
                } else if (char_count == 3) {
                    vector<string> domain{rule[2]};
                    this->rm->AddLink(rule[0], rule[1], domain);
                } else if (char_count == 4) {
                    vector<string> domain{rule[2], rule[3]};
                    this->rm->AddLink(rule[0], rule[1], domain);
                }
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