#pragma once

#ifdef CASBIN_EXPORTS
#define MODEL_API __declspec(dllexport)
#define REQUIRED_API __declspec(dllexport)
#else
#define MODEL_API __declspec(dllimport)
#define REQUIRED_API __declspec(dllimport)
#endif

#include <initializer_list>
#include <map>
#include <string>
#include <vector>

#include "../config/config.h"
#include "../rbac/role_manager.h"
#include "assertion.h"

using namespace std;

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
typedef map<string, Assertion> AssertionMap;

extern map<string, string> sectionNameMap;
// Minimal required sections for a model to be valid
extern const REQUIRED_API vector<string> requiredSections;

// Model represents the whole access control model.
class MODEL_API Model {
public:
    map<string, AssertionMap> modelmap;
    // Model creates an empty model.
    Model();
    // AddDef adds an assertion to the model.
    bool AddDef(const string sec, const string key, const string value);
    // NewModelFromFile creates a model pointer from a .CONF file.
    static Model* NewModelFromFile(const string& path);
    // NewModelFromString creates a model pointer from a string which contains model text.
    static Model* NewModelFromString(const string& text);
    // ModelFromFile creates a model from a .CONF file.
    static Model ModelFromFile(const string& path);
    // ModelFromFile creates a model from a string which contains model text.
    static Model ModelFromString(const string& text);
    // LoadModel loads the model from model CONF file.
    void LoadModel(const string& path);
    // LoadModelFromText loads the model from the text.
    void LoadModelFromText(const string& text);
    // LoadModelFromText loads the model from a config pointer.
    void LoadModelFromConfig(Config* config);
    bool HasSection(const string& sec);
    //TODO: PrintModel prints the model to the log.
    void PrintModel(void);

    // BuildRoleLinks initializes the roles in RBAC.
    void BuildRoleLinks(RoleManager* rm);
    // TODO:PrintPolicy prints the policy to log.
    void PrintPolicy(void);
    // ClearPolicy clears all current policy.
    void ClearPolicy(void);
    // GetPolicy gets all rules in a policy.
    vector<vector<string>> GetPolicy(const string& sec, const string& ptype);
    // GetFilteredPolicy gets rules based on field filters from a policy.
    vector<vector<string>> GetFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector<string>& ils);
    // HasPolicy determines whether a model has the specified policy rule.
    bool HasPolicy(const string& sec, const string& ptype, const vector<string>& rule);
    // AddPolicy adds a policy rule to the model.
    bool AddPolicy(const string& sec, const string& ptype, const vector<string>& rule);
    // AddPolicies adds policy rules to the model.
    bool AddPolicies(const string& sec, const string& ptype, const vector<vector<string>>& rules);
    // RemovePolicy removes a policy rule from the model.
    bool RemovePolicy(const string& sec, const string& ptype, const vector<string>& rule);
    // RemovePolicies removes policy rules from the model.
    bool RemovePolicies(const string& sec, const string& ptype, const vector<vector<string>>& rules);
    // RemoveFilteredPolicy removes policy rules based on field filters from the model.
    bool RemoveFilteredPolicies(const string& sec, const string& ptype, const int& fieldIndex, const vector<string>& ils);
    // GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
    vector<string> GetValuesForFieldInPolicy(const string& sec, const string& ptype, const int& fieldIndex);
    // GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all ptypes, duplicated values are removed.
    vector<string> GetValuesForFieldInPolicyAllTypes(const string& sec, const int& fieldIndex);

private:
    static bool loadAssertion(Model* model, Config* config, const string& sec, const string& key);
    static string getKeySuffix(const int& i);
    static void loadSection(Model* model, Config* config, const string& sec);
};