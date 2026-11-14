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
add_subdirectory(cpp/core)
add_subdirectory(cpp/worker)
if(GK_BUILD_BINDINGS)
  add_subdirectory(cpp/bindings)
endif()

# ---- Qt-based components: gk-ipc client and offline update verification/installation ----------
# (written by Agent B, owned by Agent A since WORK_SPLIT rev. 4). Each one is also buildable on its own
# (tests/integration/native_build.py).
option(GK_BUILD_QT_COMPONENTS "Build the Qt-based subprojects when Qt 6 is available" ON)
if(GK_BUILD_QT_COMPONENTS)
  find_package(Qt6 6.4 QUIET COMPONENTS Core)
  if(Qt6_FOUND)
    add_subdirectory(cpp/ipc)
    add_subdirectory(cpp/updates)
    add_subdirectory(cpp/scan)
    add_subdirectory(cpp/cli)
  else()
    message(STATUS "Qt 6 não encontrado: cpp/ipc e cpp/updates não entram neste build")
  endif()
endif()
