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

find_package(Python REQUIRED COMPONENTS Interpreter Development)

set(SOURCES
    main.cpp
    py_cached_enforcer.cpp
    py_enforcer.cpp
    py_model.cpp
    py_config.cpp
    py_synced_enforcer.cpp
    py_adapter.cpp
)

set(HEADERS
    py_casbin.h
)

Python_add_library(pycasbin MODULE ${SOURCES} ${HEADERS})

target_include_directories(pycasbin PUBLIC ${CASBIN_INCLUDE_DIR})

set_target_properties(pycasbin PROPERTIES
    PREFIX ""
    CXX_STANDARD 17
)

# For in-source versioning macro
add_definitions(-DPY_CASBIN_VERSION=${PY_CASBIN_VERSION})

if(WIN32)
    # Windows uses .pyd extension for python modules
    set_target_properties(pycasbin PROPERTIES
        SUFFIX ".pyd"
    )
endif()

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
        pybind11::module
        casbin
        nlohmann_json::nlohmann_json
)

if(WIN32)
    set(Python_VARIANT_PATH lib${LIB_SUFFIX}/site-packages)
else()
    set(Python_VARIANT_PATH lib${LIB_SUFFIX}/python${Python_VERSION_MAJOR}.${Python_VERSION_MINOR}/site-packages)
endif()

# For testing
install(
    TARGETS pycasbin
    LIBRARY DESTINATION ${CMAKE_SOURCE_DIR}/tests/python
)

if(CASBIN_INSTALL)
    # For actual installation
    install(
        TARGETS pycasbin
        LIBRARY DESTINATION ${Python_VARIANT_PATH}
    )

    message(STATUS "[pycasbin]: Build \"pycasbin\" target for Python Bindings")
    message(STATUS "[pycasbin]: Add \"${Python_VARIANT_PATH}\" to your sys.path/USER_SITE variable if not already present")
endif()
