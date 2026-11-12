cmake_minimum_required(VERSION 3.25)
project(GameKernel VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(GK_BUILD_BINDINGS "Build the gk_native Python module (pybind11)" ON)
option(GK_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(GK_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(GkCompilerOptions)
include(GkDependencies)

add_subdirectory(cpp/core)
if(GK_BUILD_BINDINGS)
  add_subdirectory(cpp/bindings)
endif()
