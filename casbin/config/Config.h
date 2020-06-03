#ifndef CASBIN_CPP_CONFIG_CONFIG
#define CASBIN_CPP_CONFIG_CONFIG

#include <string>
#include <sstream>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <stdio.h>
#include <algorithm>

#include "./config_interface.h"
#include "../exception/IOException.h"
#include "../exception/IllegalArgumentException.h"
#include "../util/trim.h"
#include "../util/ends_with.h"
#include "../util/split.h"

using namespace std;

class Config : public ConfigInterface {
    private: 
        static const string DEFAULT_SECTION;
        static const string DEFAULT_COMMENT;
        static const string DEFAULT_COMMENT_SEM;
        static mutex mtx_lock;

        unordered_map < string, unordered_map <string, string> > data;

        /**
         * addConfig adds a new section->key:value to the configuration.
         */
        bool addConfig(string section, string option, string value) {
            if (!section.compare("")) {
                section = DEFAULT_SECTION;
            }
            bool ok = data[section].find(option) != data[section].end();
            data[section][option] = value;
            return !ok;
        }
    
        void parse(string fname) {
            mtx_lock.lock();
            ifstream infile;
            try {
                infile.open(fname);
            } catch (const ifstream::failure e) {
                mtx_lock.unlock();
                throw IOException("Cannot open file.");
            }
            parseBuffer(&infile);
            mtx_lock.unlock();
            infile.close();
        }

        void parseBuffer(istream* buf){
            string section = "";
            int line_num = 0;
            string line;
            while (true) {
                line_num++;
                if (getline(*buf, line, '\n')) {
                    if (!line.compare("")) {
                        continue;
                    }
                } else {
                    break;
                }
                
                line = Trim(line);
                if (line.find(DEFAULT_COMMENT)==0) {
                    continue;
                } else if (line.find(DEFAULT_COMMENT_SEM)==0) {
                    continue;
                } else if (line.find("[")==0 && EndsWith(line, string("]"))) {
                    section = line.substr(1, line.length() - 2);
                } else {
                    vector <string> option_val = Split(line, string("="), 2);
                    if (option_val.size() != 2) {
                        char* error = new char;
                        sprintf(error,"parse the content error : line %d , %s = ? ", line_num, option_val[0].c_str());
                        throw IllegalArgumentException(string(error));
                    }
                    string option = Trim(option_val[0]);
                    string value = Trim(option_val[1]);
                    addConfig(section, option, value);
                }
            }
        }

    public:

        /**
         * newConfig create an empty configuration representation from file.
         *
         * @param confName the path of the model file.
         * @return the constructor of Config.
         */
        static Config* NewConfig(string conf_name) {
            Config* c = new Config;
            c->parse(conf_name);
            return c;
        }

        /**
         * newConfigFromText create an empty configuration representation from text.
         *
         * @param text the model text.
         * @return the constructor of Config.
         */
        static Config* NewConfigFromText(string text) {
            Config *c = new Config;
            stringstream stream(text);
            c->parseBuffer(&stream);
            return c;
        }

        bool GetBool(string key) {
            return Get(key).compare("true")==0;
        }

        int GetInt(string key) {
            return atoi(Get(key).c_str());
        }

        float GetFloat(string key) {
            return float(atof(Get(key).c_str()));
        }

        string GetString(string key) {
            return Get(key);
        }

        vector <string> GetStrings(string key) {
            string v = Get(key);
            if (!v.compare("")) {
                vector <string> empty;
                return empty;
            }
            return Split(v,string(","));
        }

        void Set(string key, string value) {
            mtx_lock.lock();
            if (key.length() == 0) {
                mtx_lock.unlock();
                throw IllegalArgumentException("key is empty");
            }

            string section = "";
            string option;

            transform(key.begin(), key.end(), key.begin(), ::tolower);
            vector <string> keys = Split(key, string("::"));
            if (keys.size() >= 2) {
                section = keys[0];
                option = keys[1];
            } else {
                option = keys[0];
            }
            addConfig(section, option, value);
            mtx_lock.unlock();
        }

        string Get(string key) {
            string section;
            string option;
            transform(key.begin(), key.end(), key.begin(), ::tolower);
            vector <string> keys = Split(key, string("::"));
            if (keys.size() >= 2) {
                section = keys[0];
                option = keys[1];
            } else {
                section = DEFAULT_SECTION;
                option = keys[0];
            }
            bool ok = data.find(section)!=data.end() && data[section].find(option) != data[section].end();
            if (ok) {
                return data[section][option];
            } else {
                return "";
            }
        }
};

const string Config::DEFAULT_SECTION = "default";
const string Config::DEFAULT_COMMENT = "#";
const string Config::DEFAULT_COMMENT_SEM = ";";
mutex Config::mtx_lock;

#endif