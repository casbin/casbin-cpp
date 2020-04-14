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


void Assertion::buildRoleLinks(RoleManager* rm)
{
    RM = rm;
    int cnt = count(Value.begin(), Value.end(), '_');
    for (auto rule : Policy) {
        if (cnt < 2) {
           throw exception("the number of \"_\" in role definition should be at least 2");
        }
        if (rule.size() < cnt) {
            throw exception("grouping policy elements do not meet role definition");
        }

        if (cnt == 2) {
           RM->Addlink(rule[0], rule[1], {});
        }
        else if (cnt == 3) {
           RM->Addlink(rule[0], rule[1], { rule[2] });
        }
        else if (cnt == 4) {
           RM->Addlink(rule[0], rule[1], { rule[2],rule[3] });
        }
    }

}

void Assertion::PrintAssertion() {
    cout << "------------------Assertion-------------------" << endl;
    cout << "key:" << Key << endl;
    cout << "Value:" << Value << endl;
    cout << "Tokens:";
    Util::PrintVector(Tokens);
    cout << endl;
    cout << "Policy:";
    Util::Print2DVector(Policy);
    cout << endl;
    cout << "------------------Assertion-------------------" << endl;
}