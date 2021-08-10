#  Copyright 2020 The casbin Authors. All Rights Reserved.
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

cmake_minimum_required(VERSION 3.19)

set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${CMAKE_SOURCE_DIR}/cmake/modules
)

set(CMAKE_WARN_DEPRECATED ON)
set(PY_CASBIN_VERSION 1.0)

if(APPLE AND NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
    # The value of this variable should be set prior to the first project() command invocation
    # because it may influence configuration of the toolchain and flags.
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13" CACHE STRING "Minimum OS X deployment version")
endif()

###############################################################################
# Project definition.

project(CasbinCPP
    VERSION 1.36.0
    DESCRIPTION "An authorization library that supports access control models like ACL, RBAC, ABAC in C/C++"
    HOMEPAGE_URL https://github.com/casbin/casbin-cpp
    LANGUAGES CXX C
)


###############################################################################
# Forbid in-source build.

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR 
            "In-source build not allowed. Please make a new sub-directory and run CMake from there.")
endif()

###############################################################################
# Global CMake options.

option(CASBIN_BUILD_TEST "State whether to build test" ON)
option(CASBIN_BUILD_BENCHMARK "State whether to build benchmarks" ON)
option(CASBIN_BUILD_BINDINGS "State whether to build language bindings" ON)
option(CASBIN_BUILD_PYTHON_BINDINGS "State whether to build python bindings" ON)

# Do not output install messages.
if(NOT DEFINED CMAKE_INSTALL_MESSAGE)
    set(CMAKE_INSTALL_MESSAGE "NEVER")
endif()

if(CASBIN_BUILD_BINDINGS)
    add_subdirectory(bindings)
endif()

if(CASBIN_BUILD_TEST)
    enable_testing()
    add_subdirectory(tests)
endif()

# Change the path max size to avoid problem on Windows.
if(NOT DEFINED CMAKE_OBJECT_PATH_MAX)
    set(CMAKE_OBJECT_PATH_MAX 300)
endif()

# Setting to C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)

###############################################################################
# Find or install external dependencies
# Some required targets may be created by third-party CMake configs, which 
# don't generally produce global targets. To guarantee all imported targets are 
# global, this module is included at the project root level.

include(FindExtPackages)

add_subdirectory(casbin)

export(TARGETS
    casbin
    NAMESPACE casbin::
    FILE "${CMAKE_CURRENT_BINARY_DIR}/CasbinConfig.cmake"
)

if(CASBIN_BUILD_PYTHON_BINDINGS)
    export(TARGETS pycasbin
        NAMESPACE casbin::
        FILE "${CMAKE_CURRENT_BINARY_DIR}/PyCasbinConfig.cmake"
    )
endif()