#pragma once
#include<string>
#include<vector>
using namespace std;

class Assertion {
public:
    string Key;
    string Value;
    vector<string> Tokens;
    vector<vector<string>> Policy;
    //RoleManager* RM;
    Assertion();
    void buildRoleLinks();
    void PrintAssertion();
};