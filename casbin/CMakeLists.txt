#  Copyright 2021 The casbin Authors. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

FILE(GLOB_RECURSE SRC_FILES "*.cpp" "*.h")

# Setting to C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)

add_library(casbin ${SRC_FILES})
include_directories(${CMAKE_SOURCE_DIR}/casbin)

target_precompile_headers(casbin PUBLIC "pch.h")

set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR})

set_target_properties(casbin PROPERTIES 
    PREFIX ""
)

if(WIN32 OR MSVC)
    set_target_properties(casbin PROPERTIES SUFFIX ".lib")
elseif(UNIX)
    set_target_properties(casbin PROPERTIES 
        SUFFIX ".a"
        POSITION_INDEPENDENT_CODE ON
    )
endif()

install(
    TARGETS casbin
    DESTINATION lib
)

install(
    DIRECTORY ${CMAKE_SOURCE_DIR}/casbin
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)
