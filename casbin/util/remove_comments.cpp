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

#ifndef REMOVE_COMMENTS_CPP
#define REMOVE_COMMENTS_CPP

#include "casbin/util/util.h"

namespace casbin {

// RemoveComments removes the comments starting with # in the text.
std::string RemoveComments(std::string_view s) {
    size_t pos = s.find("#");

    if (pos == std::string::npos)
        return std::string(s);

    std::string fin_str(s.substr(0, pos));
    return Trim(fin_str);
}

} // namespace casbin

#endif // REMOVE_COMMENTS_CPP
