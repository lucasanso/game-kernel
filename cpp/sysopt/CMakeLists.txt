# gk_sysopt — System Optimizer (M12): read-only diagnostics for players (power plan, Game Mode, background
# recording, GPU scheduling, memory, free space, programs that start with Windows, pending restart) and the
# two-step clean-up of old temporary files. No Windows setting is changed.
set(CMAKE_AUTOMOC ON)
find_package(Qt6 6.4 REQUIRED COMPONENTS Core)

add_library(gk_sysopt STATIC include/gk/sysopt/optimizer.hpp src/optimizer.cpp)
target_include_directories(gk_sysopt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gk_sysopt PUBLIC Qt6::Core PRIVATE gk_perf)
if(WIN32)
  target_link_libraries(gk_sysopt PRIVATE powrprof advapi32)
endif()
gk_apply_options(gk_sysopt)

if(GK_PERF_BUILD_TESTS)
  find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
  add_executable(gk_sysopt_tests tests/tst_sysopt.cpp)
  target_link_libraries(gk_sysopt_tests PRIVATE gk_sysopt Qt6::Test)
  gk_apply_options(gk_sysopt_tests)
endif()
