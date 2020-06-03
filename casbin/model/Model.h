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
#include "../exception/MissingRequiredSections.h"

unordered_map<string, string> section_name_map = {
    {"r", "request_definition"},
    {"p", "policy_definition"},
    {"g", "role_definition"},
    {"e", "policy_effect"},
    {"m", "matchers"}
};

// Minimal required sections for a model to be valid
vector<string> required_sections{"r","p","e","m"};

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
class AssertionMap {

    public:
        unordered_map<string, Assertion*> assertion_map;
};

// Model represents the whole access control model.
class Model{

    public:
        unordered_map<string, AssertionMap> m;

        // AddDef adds an assertion to the model.
        bool AddDef(string sec, string key, string value) {
            if(value == "") {
                return false;
            }

            Assertion ast;
            ast.key = key;
            ast.value = value;

            if(sec == "r" || sec == "p") {
                ast.tokens = Split(ast.value, ", ");
                for(int i = 0; i < ast.tokens.size() ; i++) {
                    ast.tokens[i] = key + "_" + ast.tokens[i];
                }
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

        void LoadModelFromConfig(ConfigInterface *cfg) {
            for(unordered_map <string, string> :: iterator it = section_name_map.begin() ; it != section_name_map.end() ; it++){
                LoadSection(*this, cfg, it->first);
            }
            vector<string> ms;
            for(vector <string> :: iterator it = required_sections.begin() ; it != required_sections.end() ; it++){
                if(!this->HasSection(*it)) {
                    ms.push_back(section_name_map[*it]);
                }
            }
            if(ms.size() > 0) {
                throw MissingRequiredSections("missing required sections: " + Join(ms, ","));
            }
        }

        bool HasSection(string sec) {
            return this->m.find(sec) != this->m.end();
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

        static bool LoadAssertion(Model model, ConfigInterface* cfg, string sec, string key) {
            string value = cfg->GetString(section_name_map[sec] + "::" + key);
            return model.AddDef(sec, key, value);
        }

        static string GetKeySuffix(int i) {
            if(i == 1) {
                return "";
            }
            stringstream ss;
            ss<<i;
            string s;
            ss>>s;
            return s;
        }

        static void LoadSection(Model model, ConfigInterface* cfg, string sec) {
            int i = 1;
            while(true) {
                if (!LoadAssertion(model, cfg, sec, sec+GetKeySuffix(i))) {
                    break;
                } else {
                    i++;
                }
            }
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

        void BuildRoleLinks(RoleManager* rm);

        void PrintPolicy();

        void ClearPolicy();

        vector<vector<string>> GetPolicy(string sec, string p_type);

        vector<vector<string>> GetFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values);

        bool HasPolicy(string sec, string p_type, vector<string> rule);

        bool AddPolicy(string sec, string p_type, vector<string> rule);

        bool RemovePolicy(string sec, string p_type, vector<string> rule);

        bool RemoveFilteredPolicy(string sec, string p_type, int field_index, vector<string> field_values);

        vector <string> GetValuesForFieldInPolicy(string sec, string p_type, int field_index);

        vector <string> GetValuesForFieldInPolicyAllTypes(string sec, int field_index);
};

#endif