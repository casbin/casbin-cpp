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

#include <string.h>

#include "./util.h"

#define LARGE 2147483647

using namespace std;

vector<string> Split(string str, string del, int limit){
    vector<string> tokens;

    if(limit<=0)
        limit = LARGE;

    for (int i = 1; i < limit ; i++) {
        size_t pos = str.find(del);
        if (pos != string::npos) {
            tokens.push_back(str.substr(0, pos));
            str = str.substr(pos + del.length());
        } else
            break;
    }
    tokens.push_back(str);

    return tokens;
}