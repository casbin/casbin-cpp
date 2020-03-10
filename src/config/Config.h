#ifndef CASBIN_CPP_CONFIG_CONFIG
#define CASBIN_CPP_CONFIG_CONFIG

#include <string>
#include <sstream>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <stdio.h>
#include <algorithm>

#include "./ConfigInterface.h"
#include "../exception/IOException.h"
#include "../exception/IllegalArgumentException.h"
#include "../util/trim.h"
#include "../util/ends_with.h"
#include "../util/split.h"

using namespace std;

mutex mtx_lock;

class Config : public ConfigInterface {
    private: 
        static const string DEFAULT_SECTION;
        static const string DEFAULT_COMMENT;
        static const string DEFAULT_COMMENT_SEM;
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
                parseBuffer(&infile);
            } catch (const ifstream::failure &e) {
                mtx_lock.unlock();
                IOException exception("Cannot open file.");
                throw exception;
            }
        }

        void parseBuffer(istream* buf){
            string section = "";
            int lineNum = 0;
            string line;

            while (true) {
                lineNum++;

                if (getline(*buf, line, '\n')) {
                    if (!line.compare("")) {
                        continue;
                    }
                } else {
                    break;
                }


                line = trim(line);
                if (line.find(DEFAULT_COMMENT)==0) {
                    continue;
                } else if (line.find(DEFAULT_COMMENT_SEM)==0) {
                    continue;
                } else if (line.find("[")==0 && ends_with(line, string("]"))) {
                    section = line.substr(1, line.length() - 1);
                } else {
                    vector <string> optionVal = split(line, string("="));
                    if (optionVal.size() != 2) {
                        char * error;
                        sprintf(error,"parse the content error : line %d , %s = ? ", lineNum, optionVal[0].c_str());
                        throw IllegalArgumentException(string(error));
                    }
                    string option = trim(optionVal[0]);
                    string value = trim(optionVal[1]);
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
        static Config newConfig(string confName) {
            Config c;
            c.parse(confName);
            return c;
        }

        /**
         * newConfigFromText create an empty configuration representation from text.
         *
         * @param text the model text.
         * @return the constructor of Config.
         */
        static Config newConfigFromText(string text) {
            Config c;
            stringstream stream(text);
            c.parseBuffer(&stream);
            return c;
        }

        bool getBool(string key) {
            return key.compare("true")==0;
        }

        int getInt(string key) {
            return atoi(get(key).c_str());
        }

        float getFloat(string key) {
            return atof(get(key).c_str());
        }

        string getString(string key) {
            return get(key);
        }

        vector <string> getStrings(string key) {
            string v = get(key);
            if (!v.compare("")) {
                vector <string> empty;
                return empty;
            }
            return split(v,string(","));
        }

        void set(string key, string value) {
            mtx_lock.lock();
            if (key.length() == 0) {
                mtx_lock.unlock();
                throw IllegalArgumentException("key is empty");
            }

            string section = "";
            string option;

            transform(key.begin(), key.end(), key.begin(), ::toupper);
            vector <string> keys = split(key, string("::"));
            if (keys.size() >= 2) {
                section = keys[0];
                option = keys[1];
            } else {
                option = keys[0];
            }
            addConfig(section, option, value);
            mtx_lock.unlock();
        }

        string get(string key) {
            string section;
            string option;

            transform(key.begin(), key.end(), key.begin(), ::toupper);
            vector <string> keys = split(key, string("::"));
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

#endif