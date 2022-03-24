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

#include "casbin/pch.h"

#ifndef ARRAY_EQUALS_CPP
#define ARRAY_EQUALS_CPP

#include <algorithm>

#include "casbin/util/util.h"

namespace casbin {

// ArrayEquals determines whether two std::string arrays are identical.
bool ArrayEquals(std::vector<std::string> a, std::vector<std::string> b) {
    if (a.size() != b.size())
        return false;

    std::sort(a.begin(), a.end());
    std::sort(b.begin(), b.end());

    return (a == b);
}

} // namespace casbin

#endif // ARRAY_EQUALS_CPP
