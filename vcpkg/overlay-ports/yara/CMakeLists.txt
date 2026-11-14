# Game Kernel build of libyara (overlay of vcpkg's ports/yara/CMakeLists.txt, YARA 4.6.0).
#
# Difference from the upstream port: no OpenSSL. The upstream port links OpenSSL::SSL and OpenSSL::Crypto
# unconditionally; with static linking that put OpenSSL's socket/HTTP code (WS2_32 imports) into every Game
# Kernel binary. Here, on Windows, libyara/crypto.h uses its Windows CryptoAPI backend (HAVE_WINCRYPT_H) for the
# hash module and pe.imphash. pe.signatures / pe.is_signed are not available: Game Kernel verifies Authenticode
# itself (cpp/core gk/authenticode.hpp). Elsewhere the hash module is left out (no crypto backend).
# The process-memory scanner is not built either (see below).
cmake_minimum_required(VERSION 3.10)
project(yara C)

if(MSVC)
  add_compile_options(/W3 /wd4005 /wd4996 /wd4018 -D_CRT_SECURE_NO_WARNINGS)
else()
  find_library(HAVE_LIBM NAMES m)
endif()

include_directories(
  .
  libyara
  libyara/include
)

# Game Kernel scans files only, never process memory: the process scanner (OpenProcess, ReadProcessMemory,
# SeDebugPrivilege via AdjustTokenPrivileges on Windows) is not compiled in.
set(PROC_PLATFORM_SOURCE "libyara/proc/none.c")
set(PROC_PLATFORM_INTERFACE "USE_NO_PROC")
if(UNIX AND CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(THREADS_PREFER_PTHREAD_FLAG TRUE)
endif()

set(
  libyara_sources
  libyara/ahocorasick.c
  libyara/arena.c
  libyara/atoms.c
  libyara/base64.c
  libyara/bitmask.c
  libyara/compiler.c
  libyara/endian.c
  libyara/exec.c
  libyara/exefiles.c
  libyara/filemap.c
  libyara/grammar.c
  libyara/hash.c
  libyara/hex_grammar.c
  libyara/hex_lexer.c
  libyara/lexer.c
  libyara/libyara.c
  libyara/mem.c
  libyara/modules.c
  libyara/modules/console/console.c
  libyara/modules/math/math.c
  libyara/modules/macho/macho.c
  libyara/modules/pe/pe.c
  libyara/modules/pe/pe_utils.c
  libyara/modules/tests/tests.c
  libyara/modules/time/time.c
  libyara/modules/string/string.c
  libyara/notebook.c
  libyara/object.c
  libyara/parser.c
  libyara/proc.c
  ${PROC_PLATFORM_SOURCE}
  libyara/re.c
  libyara/re_grammar.c
  libyara/re_lexer.c
  libyara/rules.c
  libyara/scan.c
  libyara/scanner.c
  libyara/sizedstr.c
  libyara/stack.c
  libyara/stopwatch.c
  libyara/stream.c
  libyara/strutils.c
  libyara/threading.c
  # Not built: libyara/modules/pe/authenticode-parser/* (OpenSSL), libyara/modules/elf/elf.c (needs tlshc).
)

set(
  yara_sources
  cli/args.c
  cli/common.c
  cli/threading.c
  cli/yara.c
)
set(yarac_sources
  cli/args.c
  cli/common.c
  cli/yarac.c
)

find_package(Threads REQUIRED)

set(libyara_dependencies Threads::Threads)
set(libyara_definitions -D${PROC_PLATFORM_INTERFACE})

if(WIN32)
  # libyara/crypto.h: Windows CryptoAPI backend (CryptAcquireContext/CryptCreateHash live in Advapi32).
  list(APPEND libyara_definitions -DHAVE_WINCRYPT_H -DHASH_MODULE)
  list(APPEND libyara_sources libyara/modules/hash/hash.c)
  list(APPEND libyara_dependencies advapi32)
endif()
if(HAVE_LIBM)
  list(APPEND libyara_dependencies m)
endif()

add_library(libyara ${libyara_sources})
target_link_libraries(libyara PRIVATE ${libyara_dependencies})
target_compile_definitions(libyara PRIVATE ${libyara_definitions})
target_include_directories(libyara INTERFACE $<INSTALL_INTERFACE:include>)

add_executable(yara ${yara_sources})
add_executable(yarac ${yarac_sources})

target_link_libraries(yarac PRIVATE libyara ${libyara_dependencies})
target_link_libraries(yara PRIVATE libyara ${libyara_dependencies})

install(
  TARGETS libyara EXPORT unofficial-libyaraTargets
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(EXPORT unofficial-libyaraTargets
    NAMESPACE unofficial::libyara::
    DESTINATION share/unofficial-libyara
)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/unofficial-libyara-config.cmake.in"
[[include(CMakeFindDependencyMacro)
find_dependency(Threads)
include("${CMAKE_CURRENT_LIST_DIR}/unofficial-libyaraTargets.cmake")
]])
configure_file("${CMAKE_CURRENT_BINARY_DIR}/unofficial-libyara-config.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/unofficial-libyara-config.cmake" @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/unofficial-libyara-config.cmake DESTINATION share/unofficial-libyara)

if(NOT DISABLE_INSTALL_TOOLS)
  install(
    TARGETS yarac yara
    RUNTIME DESTINATION bin
  )
endif()

if(NOT DISABLE_INSTALL_HEADERS)
  install(
    DIRECTORY libyara/include/
    DESTINATION include
    PATTERN "tlshc" EXCLUDE
  )
endif()
