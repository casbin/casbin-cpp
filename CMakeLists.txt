cmake_minimum_required(VERSION 3.19)

set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${CMAKE_SOURCE_DIR}/cmake/modules
)

set(CMAKE_WARN_DEPRECATED ON)

if(APPLE AND NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
    # The value of this variable should be set prior to the first project() command invocation
    # because it may influence configuration of the toolchain and flags.
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13" CACHE STRING "Minimum OS X deployment version")
endif()

###############################################################################
# Project definition.

project(Casbin-CPP 
    VERSION 1.0.0
    DESCRIPTION "An authorization library that supports access control models like ACL, RBAC, ABAC in C/C++"
    HOMEPAGE_URL https://github.com/casbin/casbin-cpp
    LANGUAGES CXX C)


###############################################################################
# Forbid in-source build.

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR 
            "In-source build not allowed. Please make a new sub-directory and run CMake from there.")
endif()

###############################################################################
# Global CMake options.

# Do not output install messages.
if(NOT DEFINED CMAKE_INSTALL_MESSAGE)
    set(CMAKE_INSTALL_MESSAGE "NEVER")
endif()

enable_testing()
add_subdirectory(tests)

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
