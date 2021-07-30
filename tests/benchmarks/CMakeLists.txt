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

add_executable(casbin_benchmark
    config_path.h
    main.cpp
    model_b.cpp
    enforcer_cached_b.cpp
    management_api_b.cpp
    role_manager_b.cpp
)

target_include_directories(casbin_benchmark PUBLIC ${CMAKE_SOURCE_DIR})

if(UNIX)
    set_target_properties(casbin_benchmark PROPERTIES
      POSITION_INDEPENDENT_CODE ON
    )
endif()

target_link_libraries(
    casbin_benchmark
    benchmark
    casbin
)