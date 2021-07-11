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

#ifndef FIND_ADD_OCCURENCES_CPP
#define FIND_ADD_OCCURENCES_CPP


#include "./util.h"

namespace casbin {

std::vector <size_t> FindAllOccurences(std::string data, std::string toSearch) {
    // Get the first occurrence
    size_t pos = data.find(toSearch);

    std::vector<size_t> vec;

    // Repeat till end is reached
    while (pos != std::string::npos) {
        // Add position to the vector
        vec.push_back(pos);

        // Get the next occurrence from the current position
        pos = data.find(toSearch, pos + toSearch.size());
    }
    return vec;
}

} // namespace casbin

#endif // FIND_ADD_OCCURENCES_CPP
