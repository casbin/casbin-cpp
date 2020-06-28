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

#ifndef CASBIN_CPP_CONFIG_CONFIG_INTERFACE
#define CASBIN_CPP_CONFIG_CONFIG_INTERFACE

#include <string>
#include <vector>

using namespace std;

class ConfigInterface {
    public:

        virtual string GetString(string key) = 0;
        virtual vector <string> GetStrings(string key) = 0;
        virtual bool GetBool(string key) = 0;
        virtual int GetInt(string key) = 0;
        virtual float GetFloat(string key) = 0;
        virtual void Set(string key, string value) = 0;

};

#endif