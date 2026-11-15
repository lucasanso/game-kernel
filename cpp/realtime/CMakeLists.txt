# gk_realtime — real-time protection (M11): native recursive directory watchers (ReadDirectoryChangesW on
# Windows; inotify on Linux for development and CI), the batching rules that wait for files to be fully
# written, and the monitor that scans them with gk_scan, records realtime_events and, only when the user
# turned it on, quarantines threats confirmed by a signature.
set(CMAKE_AUTOMOC ON)
find_package(Qt6 6.4 REQUIRED COMPONENTS Core)

add_library(gk_realtime STATIC
  include/gk/realtime/watcher.hpp include/gk/realtime/batcher.hpp include/gk/realtime/monitor.hpp
  src/watcher.cpp src/batcher.cpp src/monitor.cpp)
target_include_directories(gk_realtime PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gk_realtime PUBLIC gk_scan Qt6::Core)
find_package(Threads REQUIRED)
target_link_libraries(gk_realtime PRIVATE Threads::Threads)
gk_apply_options(gk_realtime)

option(GK_REALTIME_BUILD_TESTS "Build gk_realtime_tests (driven by tests/integration/test_cpp_realtime.py)" ON)
if(GK_REALTIME_BUILD_TESTS)
  find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
  add_executable(gk_realtime_tests tests/tst_realtime.cpp)
  target_link_libraries(gk_realtime_tests PRIVATE gk_realtime Qt6::Test)
  gk_apply_options(gk_realtime_tests)
  add_dependencies(gk_realtime_tests gk-scanworker)   # batches are scanned by isolated worker processes
endif()
