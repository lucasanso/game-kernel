# gk_perf — Performance Monitor (M12): CPU, memory, disk, GPU engines and video memory, busiest processes,
# measured by the operating system (GetSystemTimes, PDH counters by English name, DXGI, Toolhelp on Windows;
# /proc and /sys on Linux for development and CI). Read-only.
set(CMAKE_AUTOMOC ON)
find_package(Qt6 6.4 REQUIRED COMPONENTS Core)

add_library(gk_perf STATIC include/gk/perf/sampler.hpp src/sampler.cpp)
target_include_directories(gk_perf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gk_perf PUBLIC Qt6::Core)
if(WIN32)
  target_link_libraries(gk_perf PRIVATE pdh dxgi psapi)
endif()
gk_apply_options(gk_perf)

option(GK_PERF_BUILD_TESTS "Build gk_perf_tests and gk_sysopt_tests (driven by tests/integration/test_cpp_perf.py)" ON)
if(GK_PERF_BUILD_TESTS)
  find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
  add_executable(gk_perf_tests tests/tst_perf.cpp)
  target_link_libraries(gk_perf_tests PRIVATE gk_perf Qt6::Test)
  gk_apply_options(gk_perf_tests)
endif()
