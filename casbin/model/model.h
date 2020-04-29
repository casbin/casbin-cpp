#pragma once

#ifdef CASBIN_EXPORTS
#define MODEL_API __declspec(dllexport)
#define REQUIRED_API __declspec(dllexport)
#else
#define MODEL_API __declspec(dllimport)
#define REQUIRED_API __declspec(dllimport)
#endif

#include <string>
#include <vector>
#include <map>
#include <initializer_list>
#include "assertion.h"
#include "../config/config.h"

using namespace std;

typedef map<string, Assertion> AssertionMap;

extern map<string, string> sectionNameMap;
extern const REQUIRED_API vector<string> requiredSections;

class MODEL_API Model {

public:
    map<string, AssertionMap> modelmap;

    Model();
    //~Model();

    bool AddDef(const string sec, const string key, const string value);


    static Model* NewModelFromFile(const string& path);
    static Model* NewModelFromString(const string& text);
    static Model ModelFromFile(const string& path);
    static Model ModelFromString(const string& text);

    static bool loadAssertion(Model* model,Config* config, const string& sec, const string& key);
    static string getKeySuffix(const int& i);
    static void loadSection(Model* model, Config* config, const string& sec);
    void LoadModel(const string& path);
    void LoadModelFromText(const string& text);
    void loadModelFromConfig(Config* config);
    bool HasSection(const string& sec);
    void PrintModel(void);
    void BuildRoleLinks();
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