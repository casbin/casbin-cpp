add_executable(
  casbintest
  test_enforcer.cpp
  main.cpp
)

target_include_directories(casbintest PUBLIC ${CMAKE_SOURCE_DIR})

target_link_libraries(
  casbintest
  gtest_main
  casbin
)

include(GoogleTest)
gtest_discover_tests(casbintest)
