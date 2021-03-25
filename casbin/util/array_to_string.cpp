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

#ifndef ARRAY_TO_STRING_CPP
#define ARRAY_TO_STRING_CPP


#include "./util.h"

using namespace std;

string ArrayToString(vector<string> arr){
    string res = arr[0];
    for (auto i = 0 ; i < arr.size() ; i++)
        res += ", " + arr[i];
    return res;
}

#endif // ARRAY_TO_STRING_CPP
