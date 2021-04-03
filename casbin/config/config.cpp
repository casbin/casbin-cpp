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

#include "pch.h"

#ifndef CONFIG_CPP
#define CONFIG_CPP


#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>

#include "./config.h"
#include "../exception/io_exception.h"
#include "../exception/illegal_argument_exception.h"
#include "../util/util.h"

namespace casbin {

const std::string Config::DEFAULT_SECTION = "default";
const std::string Config::DEFAULT_COMMENT = "#";
const std::string Config::DEFAULT_COMMENT_SEM = ";";
std::mutex Config::mtx_lock;

/**
 * addConfig adds a new section->key:value to the configuration.
 */
bool Config :: AddConfig(std::string section, std::string option, std::string value) {
    if (!section.compare(""))
        section = DEFAULT_SECTION;
    bool ok = data[section].find(option) != data[section].end();
    data[section][option] = value;
    return !ok;
}

void Config :: Parse(std::string f_name) {
    mtx_lock.lock();
    std::ifstream infile;
    try {
        infile.open(f_name);
    } catch (const std::ifstream::failure e) {
        mtx_lock.unlock();
        throw IOException("Cannot open file.");
    }
    ParseBuffer(&infile);
    mtx_lock.unlock();
    infile.close();
}

void Config ::ParseBuffer(std::istream * buf) {
    std::string section = "";
    int line_num = 0;
    std::string line;
    while (true) {
        line_num++;
        if (getline(*buf, line, '\n')){
            if (!line.compare(""))
                continue;
        }
        else
            break;
        line = Trim(line);
        if (line.find(DEFAULT_COMMENT)==0)
            continue;
        else if (line.find(DEFAULT_COMMENT_SEM)==0)
            continue;
        else if (line.find("[")==0 && EndsWith(line, std::string("]")))
            section = line.substr(1, line.length() - 2);
        else {
            std::vector<std::string> option_val = Split(line, std::string("="), 2);
            if (option_val.size() != 2) {
                char* error = new char;
                sprintf(error, "parse the content error : line %d , %s = ? ", line_num, option_val[0].c_str());
                throw IllegalArgumentException(std::string(error));
            }
            std::string option = Trim(option_val[0]);
            std::string value = Trim(option_val[1]);
            AddConfig(section, option, value);
        }
    }
}

/**
 * newConfig create an empty configuration representation from file.
 *
 * @param confName the path of the model file.
 * @return the constructor of Config.
 */
std::shared_ptr<Config> Config :: NewConfig(std::string conf_name) {
    std::shared_ptr<Config> c(new Config);
    c->Parse(conf_name);
    return c;
}

/**
 * newConfigFromText create an empty configuration representation from text.
 *
 * @param text the model text.
 * @return the constructor of Config.
 */
std::shared_ptr<Config> Config :: NewConfigFromText(std::string text) {
    std::shared_ptr<Config> c(new Config);
    std::stringstream stream(text);
    c->ParseBuffer(&stream);
    return c;
}

bool Config :: GetBool(std::string key) {
    return Get(key).compare("true")==0;
}

int Config :: GetInt(std::string key) {
    return atoi(Get(key).c_str());
}

float Config :: GetFloat(std::string key) {
    return float(atof(Get(key).c_str()));
}

std::string Config :: GetString(std::string key) {
    return Get(key);
}

std::vector<std::string> Config :: GetStrings(std::string key) {
    std::string v = Get(key);
    if (!v.compare("")) {
        std::vector<std::string> empty;
        return empty;
    }
    return Split(v,std::string(","));
}

void Config :: Set(std::string key, std::string value) {
    mtx_lock.lock();
    if (key.length() == 0) {
        mtx_lock.unlock();
        throw IllegalArgumentException("key is empty");
    }

    std::string section = "";
    std::string option;

    transform(key.begin(), key.end(), key.begin(), ::tolower);
    std::vector<std::string> keys = Split(key, std::string("::"));
    if (keys.size() >= 2) {
        section = keys[0];
        option = keys[1];
    }
    else
        option = keys[0];

    AddConfig(section, option, value);
    mtx_lock.unlock();
}

std::string Config :: Get(std::string key) {
    std::string section;
    std::string option;
    transform(key.begin(), key.end(), key.begin(), ::tolower);
    std::vector<std::string> keys = Split(key, std::string("::"));
    if (keys.size() >= 2) {
        section = keys[0];
        option = keys[1];
    } else {
        section = DEFAULT_SECTION;
        option = keys[0];
    }
    bool ok = data.find(section)!=data.end() && data[section].find(option) != data[section].end();
    if (ok)
        return data[section][option];
    return "";
}

} // namespace casbin

#endif // CONFIG_CPP
