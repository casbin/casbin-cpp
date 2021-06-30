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

if(CASBIN_BUILD_TEST)
  set(CMAKE_CXX_STANDARD 17)

add_executable(
  casbintest
  built_in_functions_test.cpp
  config_test.cpp
  enforcer_test.cpp
  enforcer_cached_test.cpp
  enforcer_synced_test.cpp
  management_api_test.cpp
  model_enforcer_test.cpp
  model_test.cpp
  rbac_api_with_domains_test.cpp
  rbac_api_test.cpp
  role_manager_test.cpp
  util_test.cpp
)

  target_include_directories(casbintest PUBLIC ${CMAKE_SOURCE_DIR})

  target_link_libraries(
    casbintest
    gtest_main
    casbin
  )

  include(GoogleTest)
  gtest_discover_tests(casbintest)
endif()

if(CASBIN_BUILD_BENCHMARK)
  add_subdirectory(benchmarks)
endif()
