#pragma once
#include <string>
#include <vector>
#include <map>
#include <initializer_list>
#include "assertion.h"

using namespace std;

typedef map<string, Assertion> AssertionMap;



class Model {

public:
    map<string, AssertionMap> modelmap;
    map<string, string> sectionNameMap = {
    {"r" , "request_definition"},
    {"p" , "policy_definition"},
    {"g" , "role_definition"},
    {"e" , "policy_effect"},
    {"m" , "matchers" }
    };
    vector<string> requiredSections = { "r","p","e","m" };

    Model();
    //~Model();
    //static Model NewModelFromFile(string path);
    //static Model NewModelFromString(string text);
    //bool loadAssertion(Model model,ConfigTnterface,string sec,string key);
    bool AddDef(string sec, string key, string value);
    string getKeySuffix(int i);
    //void loadSection(Model model, ConfigInterace, string sec);
    //void LoadModel(string path);
    //void LoadModelFromText(string text);
    //void loadModelFromConfig(ConfigInterface cfg);
    //bool HasSection(string sec);
    //void PrintModel(void);

    //void BuildRoleLinke();
    void PrintPolicy();
    void ClearPolicy();
    vector<vector<string>> GetPolicy(string sec, string ptype);
    //vector<vector<string>> GetFilteredPolicy(string sec, string ptype,int fieldIndex,string ...);
    bool HasPolicy(string sec, string ptype, vector<string> rule);
    bool AddPolicy(string sec, string ptype, vector<string> rule);
    bool AddPolicies(string sec, string ptype, vector<vector<string>> rules);
    //bool RemovePolicy(string sec, string ptype, vector<string> rule);
   // bool RemovePolicies(string sec, string ptype, vector<vector<string>> rules);
    //bool RemoveFilteredPolicies(string sec, string ptype,int fieldIndex,initializer_list<string> lists);
    //vector<string> GetValuesForFieldInPolicy(string sec, string ptype, int fieldIndex);
    //vector<string> GetValuesForFieldInPolicyAllTypes(string sec, int fieldIndex);
};