project(casbin)

cmake_minimum_required(VERSION 3.16)

set(CMAKE_CXX_STANDARD 11)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

FILE(GLOB_RECURSE SC_FILES "casbin/*.cpp" "casbin/*.h")

add_library(casbin ${SC_FILES})
