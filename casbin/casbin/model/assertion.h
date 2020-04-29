#pragma once
#include<string>
#include<vector>
#include"../rbac/role_manager.h"
using namespace std;

class Assertion {
public:
    string Key;
    string Value;
    vector<string> Tokens;
    vector<vector<string>> Policy;
    RoleManager* RM;
    Assertion();
    void buildRoleLinks(RoleManager* rm);
    void PrintAssertion();
};