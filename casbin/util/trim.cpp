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

#include "./util.h"

using namespace std;

string& LTrim(string& str, const string& chars) {
    str.erase(0, str.find_first_not_of(chars));
    return str;
}
 
string& RTrim(string& str, const string& chars) {
    str.erase(str.find_last_not_of(chars) + 1);
    return str;
}
 
string Trim(string& str, const string& chars) {
    return LTrim(RTrim(str, chars), chars);
}