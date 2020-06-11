#ifndef CASBIN_CPP_CONFIG_CONFIG
#define CASBIN_CPP_CONFIG_CONFIG

#include <unordered_map>
#include <mutex>

#include "./config_interface.h"

using namespace std;

class Config : public ConfigInterface {
    private:

        static const string DEFAULT_SECTION;
        static const string DEFAULT_COMMENT;
        static const string DEFAULT_COMMENT_SEM;
        static mutex mtx_lock;

        unordered_map<string, unordered_map<string, string>> data;

        /**
         * addConfig adds a new section->key:value to the configuration.
         */
        bool AddConfig(string section, string option, string value);

        void Parse(string fname);

        void ParseBuffer(istream* buf);

    public:

        /**
         * newConfig create an empty configuration representation from file.
         *
         * @param confName the path of the model file.
         * @return the constructor of Config.
         */
        static Config* NewConfig(string conf_name);

        /**
         * newConfigFromText create an empty configuration representation from text.
         *
         * @param text the model text.
         * @return the constructor of Config.
         */
        static Config* NewConfigFromText(string text);

        bool GetBool(string key);

        int GetInt(string key);

        float GetFloat(string key);

        string GetString(string key);

        vector<string> GetStrings(string key);

        void Set(string key, string value);

        string Get(string key);
};

const string Config::DEFAULT_SECTION = "default";
const string Config::DEFAULT_COMMENT = "#";
const string Config::DEFAULT_COMMENT_SEM = ";";
mutex Config::mtx_lock;

#endif