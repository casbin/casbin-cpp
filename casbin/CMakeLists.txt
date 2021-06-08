set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

FILE(GLOB_RECURSE SC_FILES "*.cpp" "*.h")

add_library(casbin ${SC_FILES})

set_target_properties(casbin PROPERTIES PREFIX "")
set_target_properties(casbin PROPERTIES SUFFIX ".o")
