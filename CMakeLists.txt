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

# ---- Agent A: Qt-free core and its Python bindings --------------------------------------------
add_subdirectory(native/core)
if(GK_BUILD_BINDINGS)
  add_subdirectory(native/bindings)
endif()

# ---- Agent B: Qt-based integration components (gk-ipc client, offline updates) ----------------
# Each subproject is also buildable on its own (tests/native/native_build.py).
option(GK_BUILD_QT_COMPONENTS "Build the Qt-based subprojects when Qt 6 is available" ON)
if(GK_BUILD_QT_COMPONENTS)
  find_package(Qt6 6.4 QUIET COMPONENTS Core)
  if(Qt6_FOUND)
    add_subdirectory(native/ipc)
    add_subdirectory(native/updates)
  else()
    message(STATUS "Qt 6 não encontrado: native/ipc e native/updates não entram neste build")
  endif()
endif()
