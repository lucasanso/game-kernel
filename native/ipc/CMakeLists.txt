# gk_ipc — C++ client of the gk-ipc v1 helper protocol (Qt 6 Core).
# Buildable standalone (cmake -S native/ipc) or from a parent project via add_subdirectory().
cmake_minimum_required(VERSION 3.21)
project(gk_ipc VERSION 1.0.0 LANGUAGES CXX)

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()
set(CMAKE_AUTOMOC ON)

option(GK_IPC_BUILD_TESTS "Build the gk_ipc test executable" ${PROJECT_IS_TOP_LEVEL})

find_package(Qt6 6.4 REQUIRED COMPONENTS Core)

add_library(gk_ipc STATIC
  include/gk/ipc/protocol.hpp
  include/gk/ipc/helper_client.hpp
  src/protocol.cpp
  src/helper_client.cpp
)
add_library(gk::ipc ALIAS gk_ipc)
target_include_directories(gk_ipc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gk_ipc PUBLIC Qt6::Core)
target_compile_features(gk_ipc PUBLIC cxx_std_20)
if(MSVC)
  target_compile_options(gk_ipc PRIVATE /W4 /permissive- /utf-8)
  # Windows 10 API level (PROC_THREAD_ATTRIBUTE_JOB_LIST, Job Object UI limits).
  target_compile_definitions(gk_ipc PRIVATE _WIN32_WINNT=0x0A00 WINVER=0x0A00 NOMINMAX)
  target_compile_definitions(gk_ipc PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
else()
  target_compile_options(gk_ipc PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wno-sign-conversion)
endif()
# No Qt network module, no sockets: the protocol only uses anonymous pipes.
target_compile_definitions(gk_ipc PUBLIC QT_NO_CAST_FROM_BYTEARRAY QT_NO_URL_CAST_FROM_STRING)

if(GK_IPC_BUILD_TESTS)
  enable_testing()
  find_package(Qt6 6.4 REQUIRED COMPONENTS Test)
  add_executable(gk_ipc_tests tests/tst_ipc.cpp)
  target_link_libraries(gk_ipc_tests PRIVATE gk::ipc Qt6::Test)
  add_test(NAME gk_ipc_tests COMMAND gk_ipc_tests)
endif()
