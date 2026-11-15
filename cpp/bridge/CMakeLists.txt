# gk_bridge — Qt service layer of the desktop application (M13): scans in a dedicated thread, history and
# results read from SQLite, the encrypted quarantine vault and the installation integrity check, all exposed
# as QObjects with signals so the user interface never blocks and never touches gk_core directly.
set(CMAKE_AUTOMOC ON)
find_package(Qt6 6.4 REQUIRED COMPONENTS Core)

add_library(gk_bridge STATIC include/gk/bridge/services.hpp src/services.cpp)
target_include_directories(gk_bridge PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gk_bridge PUBLIC gk_scan gk_realtime gk_perf gk_sysopt Qt6::Core)
gk_apply_options(gk_bridge)

option(GK_BRIDGE_BUILD_TESTS "Build gk_bridge_tests (driven by tests/integration/test_cpp_bridge.py)" ON)
if(GK_BRIDGE_BUILD_TESTS)
  find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
  add_executable(gk_bridge_tests tests/tst_bridge.cpp)
  target_link_libraries(gk_bridge_tests PRIVATE gk_bridge Qt6::Test)
  gk_apply_options(gk_bridge_tests)
  add_dependencies(gk_bridge_tests gk-scanworker)   # scans run in isolated worker processes
endif()
