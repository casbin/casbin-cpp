#pragma once

#ifdef CASBIN_EXPORTS
#define MODEL_API __declspec(dllexport)
#else
#define MODEL_API __declspec(dllimport)
#endif

#include <string>
#include <vector>
#include <map>
#include <initializer_list>
#include "../errors/exceptions.h"
#include "assertion.h"
#include "../rbac/role_manager.h"
#include "../config/config.h"

using namespace std;

typedef map<string, Assertion> AssertionMap;

extern map<string, string> sectionNameMap;
extern const vector<string> requiredSections;

class MODEL_API Model {

public:
    map<string, AssertionMap> modelmap;

    Model();
    //~Model();
    bool AddDef(const string sec, const string key, const string value);


    static Model* NewModelFromFile(Error& err,const string& path);
    static Model* NewModelFromString(Error& err, const string& text);
    static bool loadAssertion(Model* model,Config* config, const string& sec, const string& key);
    static string getKeySuffix(const int& i);
    static void loadSection(Model* model, Config* config, const string& sec);
    Error LoadModel(const string& path);
    Error LoadModelFromText(const string& text);
    Error loadModelFromConfig(Config* config);
    bool HasSection(const string& sec);
    void PrintModel(void);
    Error BuildRoleLinks(RoleManager* rm);
    void PrintPolicy(void);
    void ClearPolicy(void);
    vector<vector<string>> GetPolicy(const string& sec, const string& ptype);
    vector<vector<string>> GetFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector<string>& ils);
    bool HasPolicy(const string& sec, const string& ptype, const  vector<string>& rule);
    bool AddPolicy(const string& sec, const  string& ptype, const  vector<string>& rule);
    bool AddPolicies(const string& sec, const  string& ptype, const vector<vector<string>>& rules);
    bool RemovePolicy(const string& sec, const  string& ptype, const  vector<string>& rule);
    bool RemovePolicies(const string& sec, const  string& ptype, const vector<vector<string>>& rules);
    bool RemoveFilteredPolicies(const string& sec, const  string& ptype, const int& fieldIndex, const vector<string>& ils);
    vector<string> GetValuesForFieldInPolicy(const string& sec, const string& ptype, const int& fieldIndex);
    vector<string> GetValuesForFieldInPolicyAllTypes(const string& sec, const int& fieldIndex);
};