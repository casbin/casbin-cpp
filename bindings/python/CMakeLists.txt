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

set(SOURCES
    main.cpp
    py_cached_enforcer.cpp
    py_enforcer.cpp
)

set(HEADERS
    py_casbin.h
)

add_library(pycasbin MODULE ${SOURCES} ${HEADERS})

target_include_directories(pycasbin PUBLIC ${CMAKE_SOURCE_DIR})

set_target_properties(pycasbin PROPERTIES
    PREFIX ""
    CXX_STANDARD 17
)

if(WIN32)
    # Windows uses .pyd extension for python modules
    set_target_properties(pycasbin PROPERTIES
        SUFFIX ".pyd"
    )
endif()


# NOTE: Depending of the compiler version pybind11 2.4.3 does not compile with C++17 so revert to c++11

if(UNIX)
    # A 'module' is a dynamic library on Linux (i.e. '-fPIC' needed),
    # but a static library on Windows.

    # If supported for the target machine, emit position-independent code
    # suitable for dynamic linking.
    set_target_properties(pycasbin PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )
endif()

# macOS demands that the linker resolve all symbols at build time
# Pass this flag to allow dynamic linking
if(APPLE)
    set_target_properties(pycasbin PROPERTIES
        LINK_FLAGS "-undefined dynamic_lookup"
    )
endif()

target_link_libraries(pycasbin
    PRIVATE
        # casbin
        pybind11::module
        casbin
)

