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

#ifndef REMOVE_COMMENTS_CPP
#define REMOVE_COMMENTS_CPP


#include "./util.h"

using namespace std;

// RemoveComments removes the comments starting with # in the text.
string RemoveComments(string s) {
    auto pos = s.find("#");
    if (pos == string::npos)
        return s;
    string fin_str = s.substr(0, pos);
    return Trim(fin_str);
}

#endif // REMOVE_COMMENTS_CPP
