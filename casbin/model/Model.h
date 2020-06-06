#ifndef CASBIN_CPP_MODEL_MODEL
#define CASBIN_CPP_MODEL_MODEL

#include <string>
#include <unordered_map>
#include <sstream>

#include "./assertion.h"
#include "../config/config.h"
#include "../util/split.h"
#include "../util/join.h"
#include "../util/remove_comments.h"
#include "../util/escape_assertion.h"
#include "../util/trim.h"
#include "../util/array_equals.h"
#include "../util/array_remove_duplicates.h"
#include "../exception/MissingRequiredSections.h"

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
class AssertionMap {
    public:

        unordered_map<string, Assertion*> assertion_map;
};

// Model represents the whole access control model.
class Model{
    private:

        static unordered_map<string, string> section_name_map;

        // Minimal required sections for a model to be valid
        static vector<string> required_sections;

        void LoadModelFromConfig(ConfigInterface *cfg) {
            for(unordered_map <string, string> :: iterator it = section_name_map.begin() ; it != section_name_map.end() ; it++)
                LoadSection(*this, cfg, it->first);

            vector<string> ms;
            for(vector<string> :: iterator it = required_sections.begin() ; it != required_sections.end() ; it++){
                if(!this->HasSection(*it))
                    ms.push_back(section_name_map[*it]);
            }
            if(ms.size() > 0)
                throw MissingRequiredSections("missing required sections: " + Join(ms, ","));
        }

        bool HasSection(string sec) {
            return this->m.find(sec) != this->m.end();
        }

        static void LoadSection(Model model, ConfigInterface* cfg, string sec) {
            int i = 1;
            while(true) {
                if (!LoadAssertion(model, cfg, sec, sec+GetKeySuffix(i)))
                    break;
                else
                    i++;
            }
        }

        static string GetKeySuffix(int i) {
            if (i == 1)
                return "";
            stringstream ss;
            ss<<i;
            string s;
            ss>>s;
            return s;
        }

        static bool LoadAssertion(Model model, ConfigInterface* cfg, string sec, string key) {
            string value = cfg->GetString(section_name_map[sec] + "::" + key);
            return model.AddDef(sec, key, value);
        }

    public:

        unordered_map<string, AssertionMap> m;

        // AddDef adds an assertion to the model.
        bool AddDef(string sec, string key, string value) {
            if(value == "")
                return false;

            Assertion ast;
            ast.key = key;
            ast.value = value;

            if (sec == "r" || sec == "p") {
                ast.tokens = Split(ast.value, ",");
                for (int i = 0; i < ast.tokens.size() ; i++)
                    ast.tokens[i] = key + "_" + Trim(ast.tokens[i]);
            }
            else
                ast.value = RemoveComments(EscapeAssertion(ast.value));

            m[sec].assertion_map[key] = &ast;
            return true;
        }

        // LoadModel loads the model from model CONF file.
        void LoadModel(string path) {
            Config* cfg = Config::NewConfig(path);
            LoadModelFromConfig(cfg);
        }

        // LoadModelFromText loads the model from the text.
        void LoadModelFromText(string text) {
            Config* cfg = Config::NewConfigFromText(text);
            LoadModelFromConfig(cfg);
        }

        // PrintModel prints the model to the log.
        void PrintModel() {
          // DefaultLogger df_logger;
            // df_logger.EnableLog(true);

            // Logger *logger = &df_logger;
            // LogUtil::SetLogger(*logger);

            // LogUtil::LogPrint("Model:");
            // for (unordered_map <string, AssertionMap> :: iterator it1 = M.begin() ; it1 != M.end() ; it1++){
            // 	for(unordered_map <string, Assertion*> :: iterator it2 = (it1->second).AMap.begin() ; it2 != (it1->second).AMap.end() ; it2++){
                    // LogUtil::LogPrintf("%s.%s: %s", it1->first, it2->first, it2->second->Value);
            // 	}
            // }
        }

        // NewModel creates an empty model.
        static Model* NewModel() {
            Model *m = new Model;
            return m;
        }

        // NewModel creates a model from a .CONF file.
        static Model* NewModelFromFile(string path) {
            Model* m;
            m = NewModel();
            m->LoadModel(path);
            return m;
        }

        // NewModel creates a model from a string which contains model text.
        static Model* NewModelFromString(string text) {
            Model* m;
            m = NewModel();
            m->LoadModelFromText(text);
            return m;
        }

        void BuildIncrementalRoleLinks(RoleManager* rm, policy_op op, string sec, string p_type, vector<vector<string>> rules) {
            if (sec == "g")
                this->m[sec].assertion_map[p_type]->BuildIncrementalRoleLinks(rm, op, rules);
        }

        // BuildRoleLinks initializes the roles in RBAC.
        void BuildRoleLinks(RoleManager* rm) {
            for (unordered_map<string, Assertion*> :: iterator it = this->m["g"].assertion_map.begin() ; it != this->m["g"].assertion_map.end() ; it++) {
                (it->second)->BuildRoleLinks(rm);
            }
        }

        // PrintPolicy prints the policy to log.
        void PrintPolicy() {
            // DefaultLogger df_logger;
            // df_logger.EnableLog(true);

            // Logger *logger = &df_logger;
            // LogUtil::SetLogger(*logger);

            // LogUtil::LogPrint("Policy:");

            // for (unordered_map<string, Assertion*> :: iterator it = this->m["p"].assertion_map.begin() ; it != this->m["p"].assertion_map.end() ; it++) {
                // LogUtil::LogPrint(it->first, ": ", (it->second)->Value, ": ", (it->second)->policy);
            // }

            // for (unordered_map<string, Assertion*> :: iterator it = this->m["g"].assertion_map.begin() ; it != this->m["g"].assertion_map.end() ; it++) {
                // LogUtil::LogPrint(it->first, ": ", (it->second)->Value, ": ", (it->second)->policy);
            // }
        }

        // ClearPolicy clears all current policy.
        void ClearPolicy() {
            for (unordered_map<string, Assertion*> :: iterator it = this->m["p"].assertion_map.begin() ; it != this->m["p"].assertion_map.end() ; it++) {
                (it->second)->policy.clear();
            }

            for (unordered_map<string, Assertion*> :: iterator it = this->m["g"].assertion_map.begin() ; it != this->m["g"].assertion_map.end() ; it++) {
                (it->second)->policy.clear();
            }
        }

        // GetPolicy gets all rules in a policy.
        vector<vector<string>> GetPolicy(string sec, string p_type) {
            return (this->m)[sec].assertion_map[p_type]->policy;
        }

        // GetFilteredPolicy gets rules based on field filters from a policy.
        vector<vector<string>> GetFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values) {
            vector<vector<string>> res;

            for (vector<vector<string>> :: iterator it = m[sec].assertion_map[p_type]->policy.begin() ; it != m[sec].assertion_map[p_type]->policy.end() ; it++){
                bool matched = true;
                for(int i = 0 ; i < field_values.size() ; i++){
                    if(field_values[i] != "" && (*it)[field_index + i] != field_values[i] ){
                        matched = false;
                        break;
                    }
                }
                if(matched) {
                    res.push_back(*it);
                }
            }

            return res;
        }

        // HasPolicy determines whether a model has the specified policy rule.
        bool HasPolicy(string sec, string p_type, vector<string> rule) {
            for (vector<vector<string>> :: iterator it = m[sec].assertion_map[p_type]->policy.begin() ; it != m[sec].assertion_map[p_type]->policy.end() ; it++) {
                if (ArrayEquals(rule, *it)) {
                    return true;
                }
            }

            return false;
        }

        // AddPolicy adds a policy rule to the model.
        bool AddPolicy(string sec, string p_type, vector<string> rule) {
            if(!this->HasPolicy(sec, p_type, rule)) {
                m[sec].assertion_map[p_type]->policy.push_back(rule);
                return true;
            }
            return false;
        }

        // AddPolicies adds policy rules to the model.
        bool AddPolicies(string sec, string p_type, vector<vector<string>> rules) {
            for (int i = 0; i < rules.size(); i++)
                if (this->HasPolicy(sec, p_type, rules[i]))
                    return false;

            for (int i = 0; i < rules.size(); i++)
                this->m[sec].assertion_map[p_type]->policy.push_back(rules[i]);

            return true;
        }

        // RemovePolicy removes a policy rule from the model.
        bool RemovePolicy(string sec, string p_type, vector<string> rule) {
            for (int i = 0 ; i < m[sec].assertion_map[p_type]->policy.size() ; i++) {
                if (ArrayEquals(rule, m[sec].assertion_map[p_type]->policy[i])) {
                    m[sec].assertion_map[p_type]->policy.erase(m[sec].assertion_map[p_type]->policy.begin() + i);
                    return true;
                }
            }

            return false;
        }

        // RemovePolicies removes policy rules from the model.
        bool RemovePolicies(string sec, string p_type, vector<vector<string>> rules) {
            OUTER: for (int j = 0; j < rules.size(); j++) {
                for (int i = 0; i < this->m[sec].assertion_map[p_type]->policy.size(); i++)
                    if (ArrayEquals(rules[j], this->m[sec].assertion_map[p_type]->policy[i])) {
                        goto OUTER;
                }
                return false;
            }

            for (int j = 0; j < rules.size(); j++)
                for (int i = 0; i < this->m[sec].assertion_map[p_type]->policy.size(); i++)
                    if (ArrayEquals(rules[j], this->m[sec].assertion_map[p_type]->policy[i]))
                        this->m[sec].assertion_map[p_type]->policy.erase(this->m[sec].assertion_map[p_type]->policy.begin() + i);

            return true;
        }

        // RemoveFilteredPolicy removes policy rules based on field filters from the model.
        pair<bool, <vector<vector<string>>>> RemoveFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values) {
            vector<vector<string>> tmp;
            vector<vector<string>> effects;
            bool res = false;
            for (vector<vector< string>> :: iterator it = m[sec].assertion_map[p_type]->policy.begin() ; it != m[sec].assertion_map[p_type]->policy.end() ; it++) {
                bool matched = true;
                for (int i = 0 ; i < field_values.size() ; i++) {
                    if (field_values[i] != "" && (*it)[field_index+i] != field_values[i]) {
                        matched = false;
                        break;
                    }
                }
                if (matched){
                    effects.push_back(*it);
                    res = true;
                }
                else
                    tmp.push_back(*it);
            }

            m[sec].assertion_map[p_type]->policy = tmp;
            pair<bool, vector<vector<string>>> result(res, effects);
            return result;
        }

        // GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
        vector<string> GetValuesForFieldInPolicy(string sec, string p_type, int field_index) {
            vector<string> values;

            for (vector<vector<string>> :: iterator it = m[sec].assertion_map[p_type]->policy.begin() ; it != m[sec].assertion_map[p_type]->policy.end() ; it++){
                values.push_back((*it)[field_index]);
            }

            ArrayRemoveDuplicates(values);

            return values;
        }

        // GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all p_types, duplicated values are removed.
        vector<string> GetValuesForFieldInPolicyAllTypes(string sec, int field_index) {
            vector<string> values;

            for (unordered_map<string, Assertion*> :: iterator it = m[sec].assertion_map.begin() ; it != m[sec].assertion_map.end() ; it++) {
                for (vector<string> :: iterator it1 = this->GetValuesForFieldInPolicy(sec, it->first, field_index).begin() ; it1 != this->GetValuesForFieldInPolicy(sec, it->first, field_index).end() ; it1++) {
                    values.push_back(*it1);
                }
            }

            ArrayRemoveDuplicates(values);

            return values;
        }
};

unordered_map<string, string> Model :: section_name_map = {
    {"r", "request_definition"},
    {"p", "policy_definition"},
    {"g", "role_definition"},
    {"e", "policy_effect"},
    {"m", "matchers"}
};

vector<string> Model :: required_sections{"r","p","e","m"};

#endif