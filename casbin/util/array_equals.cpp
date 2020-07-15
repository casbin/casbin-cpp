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

#include <algorithm>

#include "./util.h"

using namespace std;

// ArrayEquals determines whether two string arrays are identical.
bool ArrayEquals(vector<string> a, vector<string> b) {
    if (a.size() != b.size()) {
        return false;
    }

    sort(a.begin(), a.end());
    sort(b.begin(), b.end());
    for (int i = 0 ; i < a.size() ; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}