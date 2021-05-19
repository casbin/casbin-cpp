set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

FILE(GLOB_RECURSE SC_FILES "*.cpp" "*.h")

add_library(casbin ${SC_FILES})
