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

set(CMAKE_WARN_DEPRECATED ON)
set(PY_CASBIN_VERSION 1.1)

if(APPLE AND NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
    # The value of this variable should be set prior to the first project() command invocation
    # because it may influence configuration of the toolchain and flags.
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13" CACHE STRING "Minimum OS X deployment version")
endif()

if(WIN32)
    add_compile_options("/bigobj")
endif()

###############################################################################
# Project definition.

project(
    casbin
    VERSION 1.53.2
    DESCRIPTION "An authorization library that supports access control models like ACL, RBAC, ABAC in C/C++"
    HOMEPAGE_URL https://github.com/casbin/casbin-cpp
    LANGUAGES CXX C
)

set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${PROJECT_SOURCE_DIR}/cmake/modules
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
option(INTENSIVE_BENCHMARK "State whether to build intensive benchmarks" OFF)
option(CASBIN_BUILD_PYTHON_BINDINGS "State whether to build python bindings" ON)
option(CASBIN_INSTALL "State whether to install casbin targets on the current system" ON)

# Intrinsic directory paths
set(CASBIN_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/casbin)
set(CASBIN_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CASBIN_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Do not output install messages.
if(NOT DEFINED CMAKE_INSTALL_MESSAGE)
    set(CMAKE_INSTALL_MESSAGE "LAZY")
endif()

# Change the path max size to avoid problem on Windows.
if(NOT DEFINED CMAKE_OBJECT_PATH_MAX)
    set(CMAKE_OBJECT_PATH_MAX 300)
endif()

# Setting to C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)

###############################################################################
# Install external dependencies
# Some required targets may be created by third-party CMake configs, which 
# don't generally produce global targets. To guarantee all imported targets are 
# global, this module is included at the project root level.

include(FindExtPackages)

add_subdirectory(casbin)

if(CASBIN_BUILD_PYTHON_BINDINGS)
    add_subdirectory(pycasbin)
endif()

if(CASBIN_BUILD_TEST)
    enable_testing()
    add_subdirectory(tests)
endif()

##########################################
# "make format"
# "make check-format"
# Only support clang format for unix like operating system.

if(UNIX)
    # Expected directory structure.
    set(CASBIN_BUILD_SUPPORT_DIR "${CMAKE_SOURCE_DIR}/build_support")
    set(CASBIN_CLANG_SEARCH_PATH "/usr/local/bin" "/usr/bin" "/usr/local/opt/llvm/bin" "/usr/local/opt/llvm@8/bin"
            "/usr/local/Cellar/llvm/8.0.1/bin")

    # clang-format
    if (NOT DEFINED CLANG_FORMAT_BIN)
        # attempt to find the binary if user did not specify
        find_program(CLANG_FORMAT_BIN
                NAMES clang-format clang-format-8
                HINTS ${CASBIN_CLANG_SEARCH_PATH})
    endif()
    if ("${CLANG_FORMAT_BIN}" STREQUAL "CLANG_FORMAT_BIN-NOTFOUND")
        message(WARNING "Casbin couldn't find clang-format.")
    else()
        message(STATUS "Casbin found clang-format at ${CLANG_FORMAT_BIN}")
    endif()

    # clang-tidy
    if (NOT DEFINED CLANG_TIDY_BIN)
        # attempt to find the binary if user did not specify
        find_program(CLANG_TIDY_BIN
                NAMES clang-tidy clang-tidy-8
                HINTS ${CASBIN_CLANG_SEARCH_PATH})
    endif()
    if ("${CLANG_TIDY_BIN}" STREQUAL "CLANG_TIDY_BIN-NOTFOUND")
        message(WARNING "Casbin couldn't find clang-tidy.")
    else()
        # Output compile_commands.json
        set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
        message(STATUS "Casbin found clang-tidy at ${CLANG_TIDY_BIN}")
    endif()

    string(CONCAT CASBIN_FORMAT_DIRS
            "${CASBIN_SOURCE_DIR},"
            "${CASBIN_INCLUDE_DIR},"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests,"
            )


    # runs clang format and updates files in place.
    add_custom_target(format ${CASBIN_BUILD_SUPPORT_DIR}/run_clang_format.py
            ${CLANG_FORMAT_BIN}
            ${CASBIN_BUILD_SUPPORT_DIR}/clang_format_exclusions.txt
            --source_dirs
            ${CASBIN_FORMAT_DIRS}
            --format_style
            "file"
            --fix
            --quiet
            )

    # runs clang format and exits with a non-zero exit code if any files need to be reformatted
    add_custom_target(check-format ${CASBIN_BUILD_SUPPORT_DIR}/run_clang_format.py
            ${CLANG_FORMAT_BIN}
            ${CASBIN_BUILD_SUPPORT_DIR}/clang_format_exclusions.txt
            --source_dirs
            ${CASBIN_FORMAT_DIRS}
            --format_style
            "file"
            --quiet
            )
endif()
##########################################
# Install casbin

if(CASBIN_INSTALL)
    message(CHECK_START "[casbin]: Installing casbin ...")
    export(
        TARGETS casbin
        NAMESPACE casbin::
        FILE casbinConfig.cmake
    )

    # Installing headers
    install(
        DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/casbin
        DESTINATION include
    )

    set(CMAKE_EXPORT_PACKAGE_REGISTRY ON)
    export(PACKAGE casbin)

    message(CHECK_PASS " The targets can now be imported with find_package(casbin)")
    message(STATUS "[casbin]: Build the \"install\" target and add \"${CMAKE_INSTALL_PREFIX}/include\" to you PATH for casbin to work")
endif()
