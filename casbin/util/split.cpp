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

#ifndef SPLIT_CPP
#define SPLIT_CPP


#include <string.h>

#include "./util.h"

#define LARGE 2147483647

using namespace std;


vector<string> Split(string src,string del) {
    string::size_type start=src.find_first_not_of(del,0);
    string::size_type pos=src.find_first_of(del,start);
    vector<string> dest;
    while(string::npos != pos || string::npos != start) {
        dest.emplace_back(src.substr(start,pos-start));
        start=src.find_first_not_of(del,pos);
        pos=src.find_first_of(del,start);
    }
    return dest;
}

#endif // SPLIT_CPP
