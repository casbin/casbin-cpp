#include "assertion.h"
#include "../util/util.h"
#include"../errors/exceptions.h"
#include <iostream>

using namespace std;
Assertion::Assertion()
{
    Key = "";
    Value = "";
    Tokens = {};
    Policy = {};
}


Error Assertion::buildRoleLinks(RoleManager* rm)
{
    RM = rm;
    int cnt = count(Value.begin(), Value.end(), '_');
    for (auto rule : Policy) {
        if (cnt < 2) {
           return Error("the number of \"_\" in role definition should be at least 2");
        }
        if (rule.size() < cnt) {
           return Error("grouping policy elements do not meet role definition");
        }

        if (cnt == 2) {
            Error err = RM->Addlink(rule[0], rule[1], {});
            if (!err.IsNull()) {
                return err;
            }
        }
        else if (cnt == 3) {
            Error err = RM->Addlink(rule[0], rule[1], { rule[2] });
            if (!err.IsNull()) {
                return err;
            }
        }
        else if (cnt == 4) {
            Error err = RM->Addlink(rule[0], rule[1], { rule[2],rule[3] });
            if (!err.IsNull()) {
                return err;
            }
        }
    }
    return Error();
}

void Assertion::PrintAssertion() {
   
}