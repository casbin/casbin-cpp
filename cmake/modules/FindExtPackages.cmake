###############################################################################
### Global package options ###

set(CMAKE_FIND_PACKAGE_NO_PACKAGE_REGISTRY ON CACHE BOOL
    "Disable CMake User Package Registry when finding packages")

set(CMAKE_FIND_PACKAGE_NO_SYSTEM_PACKAGE_REGISTRY ON CACHE BOOL
    "Disable CMake System Package Registry when finding packages")

###############################################################################
### Packages and versions ###

# googletest
# https://github.com/google/googletest
find_package(googletest 1.11.0 REQUIRED)
