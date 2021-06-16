set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

FILE(GLOB_RECURSE SRC_FILES "*.cpp" "*.h")

add_library(casbin ${SRC_FILES})
include_directories(${CMAKE_SOURCE_DIR}/casbin)

target_precompile_headers(casbin PUBLIC "pch.h")

set_target_properties(casbin PROPERTIES PREFIX "")
if(WIN32 OR MSVC)
    set_target_properties(casbin PROPERTIES SUFFIX ".lib")
elseif(UNIX)
    set_target_properties(casbin PROPERTIES SUFFIX ".a")
endif()
