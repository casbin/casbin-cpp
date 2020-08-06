/*
* Copyright 2020 The casbin Authors. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef CASBIN_CPP_CONFIG_CONFIG
#define CASBIN_CPP_CONFIG_CONFIG

#include <memory>
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

        void Parse(string f_name);

        void ParseBuffer(istream* buf);

    public:

        /**
         * NewConfig create an empty configuration representation from file.
         *
         * @param confName the path of the model file.
         * @return the constructor of Config.
         */
        static shared_ptr<Config> NewConfig(string conf_name);

        /**
         * newConfigFromText create an empty configuration representation from text.
         *
         * @param text the model text.
         * @return the constructor of Config.
         */
        static shared_ptr<Config> NewConfigFromText(string text);

        bool GetBool(string key);

        int GetInt(string key);

        float GetFloat(string key);

        string GetString(string key);

        vector<string> GetStrings(string key);

        void Set(string key, string value);

        string Get(string key);
};

#endif