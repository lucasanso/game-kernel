# Game Kernel desktop application (Agent B): Qt 6 Widgets, C++20.
# Buildable standalone (cmake -S native/app) — it then also builds native/ipc and native/updates —
# or from the root build via add_subdirectory(native/app).
cmake_minimum_required(VERSION 3.21)
project(gk_app VERSION 1.0.0 LANGUAGES CXX)

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()
set(CMAKE_AUTOMOC ON)

option(GK_APP_BUILD_TESTS "Build the gk_app_tests executable" ${PROJECT_IS_TOP_LEVEL})

find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Svg Concurrent)

if(NOT TARGET gk::ipc)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../ipc ${CMAKE_CURRENT_BINARY_DIR}/gk_ipc)
endif()
if(NOT TARGET gk::updates)
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../updates ${CMAKE_CURRENT_BINARY_DIR}/gk_updates)
endif()

add_library(gk_app_lib STATIC
  src/ui_kit.hpp src/ui_kit.cpp
  src/app_context.hpp src/app_context.cpp
  src/main_window.hpp src/main_window.cpp
  src/pages/updates_page.hpp src/pages/updates_page.cpp
  src/pages/helper_pages.hpp src/pages/helper_pages.cpp
)
target_include_directories(gk_app_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(gk_app_lib PUBLIC Qt6::Widgets Qt6::Svg Qt6::Concurrent gk::ipc gk::updates)
if(MSVC)
  target_compile_options(gk_app_lib PRIVATE /W4 /permissive- /utf-8)
else()
  target_compile_options(gk_app_lib PRIVATE -Wall -Wextra -Wpedantic)
endif()
# No Qt network module: the application never opens connections (docs/PRIVACY.md).

add_executable(GameKernel WIN32 src/main.cpp)
target_link_libraries(GameKernel PRIVATE gk_app_lib)
if(MSVC)
  target_compile_options(GameKernel PRIVATE /utf-8)
endif()

if(GK_APP_BUILD_TESTS)
  enable_testing()
  find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
  add_executable(gk_app_tests tests/tst_app.cpp)
  target_link_libraries(gk_app_tests PRIVATE gk_app_lib Qt6::Test)
  if(MSVC)
    target_compile_options(gk_app_tests PRIVATE /utf-8)
  endif()
  add_test(NAME gk_app_tests COMMAND gk_app_tests)
endif()
