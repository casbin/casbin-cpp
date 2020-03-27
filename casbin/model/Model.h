#ifndef CASBIN_CPP_MODEL_MODEL
#define CASBIN_CPP_MODEL_MODEL

#include <string>
#include <unordered_map>
#include <sstream>

#include "./Assertion.h"
#include "../config/Config.h"
#include "../util/split.h"
#include "../util/join.h"
#include "../util/removeComments.h"
#include "../util/escapeAssertion.h"
#include "../exception/MissingRequiredSections.h"

unordered_map < string, string > sectionNameMap = {
	{"r", "request_definition"},
	{"p", "policy_definition"},
	{"g", "role_definition"},
	{"e", "policy_effect"},
	{"m", "matchers"}
};

// Minimal required sections for a model to be valid
vector <string> requiredSections{"r","p","e","m"};

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
class AssertionMap {

    public:
        unordered_map < string, Assertion* > AMap;
};

// Model represents the whole access control model.
class Model{

    public:
        unordered_map < string, AssertionMap > M;

        // AddDef adds an assertion to the model.
        bool AddDef(string sec, string key, string value) {
            if(value == "") {
                return false;
            }

            Assertion ast;
            ast.Key = key;
            ast.Value = value;

            if(sec == "r" || sec == "p") {
                ast.Tokens = split(ast.Value, ", ");
                for(int i = 0; i < ast.Tokens.size() ; i++) {
                    ast.Tokens[i] = key + "_" + ast.Tokens[i];
                }
            } else {
                ast.Value = removeComments(escapeAssertion(ast.Value));
            }

            M[sec].AMap[key] = &ast;
            return true;
        }

		// LoadModel loads the model from model CONF file.
		void LoadModel(string path) {
			Config cfg = Config::newConfig(path);
			LoadModelFromConfig(&cfg);
		}

		// LoadModelFromText loads the model from the text.
		void LoadModelFromText(string text) {
			Config cfg = Config::newConfigFromText(text);
			LoadModelFromConfig(&cfg);
		}

		void LoadModelFromConfig(ConfigInterface *cfg) {
			for(unordered_map <string, string> :: iterator it = sectionNameMap.begin() ; it != sectionNameMap.end() ; it++){
				loadSection(*this, cfg, it->first);
			}
			vector <string> ms;
			for(vector <string> :: iterator it = requiredSections.begin() ; it != requiredSections.end() ; it++){
				if(!this->hasSection(*it)) {
					ms.push_back(sectionNameMap[*it]);
				}
			}
			if(ms.size() > 0) {
				throw MissingRequiredSections("missing required sections: " + join(ms, ","));
			}
		}

		bool hasSection(string sec) {
			return this->M.find(sec) != this->M.end();
		}
        
        // PrintModel prints the model to the log.
        void PrintModel() {
			DefaultLogger df_logger;
            df_logger.EnableLog(true);

            Logger *logger = &df_logger;
            LogUtil::SetLogger(*logger);

			LogUtil::LogPrint("Model:");
			for (unordered_map <string, AssertionMap> :: iterator it1 = M.begin() ; it1 != M.end() ; it1++){
				for(unordered_map <string, Assertion*> :: iterator it2 = (it1->second).AMap.begin() ; it2 != (it1->second).AMap.end() ; it2++){
					LogUtil::LogPrintf("%s.%s: %s", it1->first, it2->first, it2->second->Value);
				}
			}
        }

		static bool loadAssertion(Model model, ConfigInterface* cfg, string sec, string key) {
			string value = cfg->getString(sectionNameMap[sec] + "::" + key);
			return model.AddDef(sec, key, value);
		}

		static string getKeySuffix(int i) {
			if(i == 1) {
				return "";
			}
			stringstream ss;
			ss<<i;
			string s;
			ss>>s;
			return s;
		}

		static void loadSection(Model model, ConfigInterface* cfg, string sec) {
			int i = 1;
			while(true) {
				if (!loadAssertion(model, cfg, sec, sec+getKeySuffix(i))) {
					break;
				} else {
					i++;
				}
			}
		}

		// NewModel creates an empty model.
		static Model NewModel() {
			Model m;
			return m;
		}

		// NewModel creates a model from a .CONF file.
		static Model NewModelFromFile(string path) {
			Model m;
			m = NewModel();
			m.LoadModel(path);
			return m;
		}

		// NewModel creates a model from a string which contains model text.
		static Model NewModelFromString(string text) {
			Model m;
			m = NewModel();
			m.LoadModelFromText(text);
			return m;
		}

		void BuildRoleLinks(RoleManager* rm);

		void PrintPolicy();

		void ClearPolicy();

		vector < vector < string > > GetPolicy(string sec, string ptype);

		vector < vector < string > > GetFilteredPolicy(string sec, string ptype, int fieldIndex, vector <string> fieldValues);

		bool HasPolicy(string sec, string ptype, vector <string> rule);

		bool AddPolicy(string sec, string ptype,  vector <string> rule);

		bool RemovePolicy(string sec, string ptype, vector <string> rule);

		bool RemoveFilteredPolicy(string sec, string ptype, int fieldIndex, vector <string> fieldValues);

		vector <string> GetValuesForFieldInPolicy(string sec, string ptype, int fieldIndex);

		vector <string> GetValuesForFieldInPolicyAllTypes(string sec, int fieldIndex);
};

#endif