# gk_updates — verification and atomic installation of signed offline update packages (.gkpkg).
# Dependencies: Qt 6 Core, libsodium (Ed25519), optional libyara (rule compilation check).
# Buildable standalone (cmake -S native/updates) or via add_subdirectory().
cmake_minimum_required(VERSION 3.21)
project(gk_updates VERSION 1.0.0 LANGUAGES CXX)

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

option(GK_UPDATES_WITH_YARA "Compile YARA rules during validation (requires libyara)" ON)
option(GK_UPDATES_BUILD_CLI "Build the gk-update command-line tool" ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core)

# libsodium: vcpkg (Windows) ships a CMake config; Linux distributions ship pkg-config files.
find_package(unofficial-sodium CONFIG QUIET)
if(TARGET unofficial-sodium::sodium)
  set(GK_SODIUM_TARGET unofficial-sodium::sodium)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
  set(GK_SODIUM_TARGET PkgConfig::SODIUM)
endif()

add_library(gk_updates STATIC
  include/gk/updates/package.hpp
  include/gk/updates/validators.hpp
  include/gk/updates/installer.hpp
  src/package.cpp
  src/validators.cpp
  src/installer.cpp
)
add_library(gk::updates ALIAS gk_updates)
target_include_directories(gk_updates PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(gk_updates PUBLIC Qt6::Core PRIVATE ${GK_SODIUM_TARGET})
target_compile_features(gk_updates PUBLIC cxx_std_20)
target_compile_definitions(gk_updates PUBLIC QT_NO_CAST_FROM_BYTEARRAY)

if(GK_UPDATES_WITH_YARA)
  # vcpkg (Windows): static libyara exported with its dependencies (OpenSSL::Crypto, Crypt32, Ws2_32).
  # Note: Ws2_32 is pulled in by libyara for byte-order helpers (htonl/ntohl), not for sockets.
  find_package(unofficial-libyara CONFIG QUIET)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND AND NOT TARGET unofficial::libyara::libyara)
    pkg_check_modules(YARA QUIET IMPORTED_TARGET yara)
  endif()
  if(TARGET unofficial::libyara::libyara)
    target_link_libraries(gk_updates PRIVATE unofficial::libyara::libyara)
    target_compile_definitions(gk_updates PRIVATE GK_UPDATES_HAVE_YARA)
    message(STATUS "gk_updates: validação YARA com libyara (vcpkg)")
  elseif(TARGET PkgConfig::YARA)
    target_link_libraries(gk_updates PRIVATE PkgConfig::YARA)
    target_compile_definitions(gk_updates PRIVATE GK_UPDATES_HAVE_YARA)
    message(STATUS "gk_updates: validação YARA com libyara ${YARA_VERSION}")
  else()
    find_library(YARA_LIBRARY NAMES yara libyara)
    find_path(YARA_INCLUDE_DIR yara.h)
    if(YARA_LIBRARY AND YARA_INCLUDE_DIR)
      target_link_libraries(gk_updates PRIVATE ${YARA_LIBRARY})
      target_include_directories(gk_updates PRIVATE ${YARA_INCLUDE_DIR})
      target_compile_definitions(gk_updates PRIVATE GK_UPDATES_HAVE_YARA)
    else()
      message(WARNING "gk_updates: libyara não encontrada — componentes YARA serão recusados (falha fechada)")
    endif()
  endif()
endif()

if(MSVC)
  target_compile_options(gk_updates PRIVATE /W4 /permissive- /utf-8)
  # Windows 10 API level (PROC_THREAD_ATTRIBUTE_JOB_LIST, Job Object UI limits).
  target_compile_definitions(gk_updates PRIVATE _WIN32_WINNT=0x0A00 WINVER=0x0A00 NOMINMAX)
else()
  target_compile_options(gk_updates PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wno-sign-conversion)
endif()

if(GK_UPDATES_BUILD_CLI)
  add_executable(gk-update tools/gk_update_cli.cpp)
  target_link_libraries(gk-update PRIVATE gk::updates)
  if(MSVC)
    target_compile_options(gk-update PRIVATE /utf-8)
  endif()
endif()
