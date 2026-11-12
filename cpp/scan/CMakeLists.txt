# gk_scan — scan orchestrator (Qt Core): workers over gk-ipc, ClamAV batch, reputation, risk, SQLite.
set(CMAKE_AUTOMOC ON)
add_library(gk_scan STATIC include/gk/scan/scanner.hpp src/scanner.cpp)
target_include_directories(gk_scan PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gk_scan PUBLIC Qt6::Core gk_core gk::ipc)
gk_apply_options(gk_scan)
