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

#pragma once

#include "pch.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>

#include "./config.h"
#include "../exception/io_exception.h"
#include "../exception/illegal_argument_exception.h"
#include "../util/util.h"

const string Config::DEFAULT_SECTION = "default";
const string Config::DEFAULT_COMMENT = "#";
const string Config::DEFAULT_COMMENT_SEM = ";";
mutex Config::mtx_lock;

/**
 * addConfig adds a new section->key:value to the configuration.
 */
bool Config :: AddConfig(string section, string option, string value) {
    if (!section.compare(""))
        section = DEFAULT_SECTION;
    bool ok = data[section].find(option) != data[section].end();
    data[section][option] = value;
    return !ok;
}

void Config :: Parse(string f_name) {
    mtx_lock.lock();
    ifstream infile;
    try {
        infile.open(f_name);
    } catch (const ifstream::failure e) {
        mtx_lock.unlock();
        throw IOException("Cannot open file.");
    }
    ParseBuffer(&infile);
    mtx_lock.unlock();
    infile.close();
}

void Config :: ParseBuffer(istream* buf){
    string section = "";
    int line_num = 0;
    string line;
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
        else if (line.find("[")==0 && EndsWith(line, string("]")))
            section = line.substr(1, line.length() - 2);
        else {
            vector<string> option_val = Split(line, string("="), 2);
            if (option_val.size() != 2) {
                char* error = new char;
                sprintf(error, "parse the content error : line %d , %s = ? ", line_num, option_val[0].c_str());
                throw IllegalArgumentException(string(error));
            }
            string option = Trim(option_val[0]);
            string value = Trim(option_val[1]);
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
shared_ptr<Config> Config :: NewConfig(string conf_name) {
    shared_ptr<Config> c(new Config);
    c->Parse(conf_name);
    return c;
}

/**
 * newConfigFromText create an empty configuration representation from text.
 *
 * @param text the model text.
 * @return the constructor of Config.
 */
shared_ptr<Config> Config :: NewConfigFromText(string text) {
    shared_ptr<Config> c(new Config);
    stringstream stream(text);
    c->ParseBuffer(&stream);
    return c;
}

bool Config :: GetBool(string key) {
    return Get(key).compare("true")==0;
}

int Config :: GetInt(string key) {
    return atoi(Get(key).c_str());
}

float Config :: GetFloat(string key) {
    return float(atof(Get(key).c_str()));
}

string Config :: GetString(string key) {
    return Get(key);
}

vector<string> Config :: GetStrings(string key) {
    string v = Get(key);
    if (!v.compare("")) {
        vector<string> empty;
        return empty;
    }
    return Split(v,string(","));
}

void Config :: Set(string key, string value) {
    mtx_lock.lock();
    if (key.length() == 0) {
        mtx_lock.unlock();
        throw IllegalArgumentException("key is empty");
    }

    string section = "";
    string option;

    transform(key.begin(), key.end(), key.begin(), ::tolower);
    vector<string> keys = Split(key, string("::"));
    if (keys.size() >= 2) {
        section = keys[0];
        option = keys[1];
    }
    else
        option = keys[0];

    AddConfig(section, option, value);
    mtx_lock.unlock();
}

string Config :: Get(string key) {
    string section;
    string option;
    transform(key.begin(), key.end(), key.begin(), ::tolower);
    vector<string> keys = Split(key, string("::"));
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