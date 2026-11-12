# Locates third-party libraries both with vcpkg (Windows, CMake configs) and with system packages
# (Linux development, pkg-config). Every dependency is exposed as a gk::<name> target.
find_package(PkgConfig QUIET)

# ---- libsodium ------------------------------------------------------------------------------
find_package(unofficial-sodium CONFIG QUIET)
if(TARGET unofficial-sodium::sodium)
  add_library(gk::sodium ALIAS unofficial-sodium::sodium)
elseif(PKG_CONFIG_FOUND)
  pkg_check_modules(GK_SODIUM REQUIRED IMPORTED_TARGET libsodium)
  add_library(gk::sodium ALIAS PkgConfig::GK_SODIUM)
else()
  message(FATAL_ERROR "libsodium não encontrada (vcpkg: libsodium; apt: libsodium-dev)")
endif()

# ---- nlohmann/json (header-only) ------------------------------------------------------------
find_package(nlohmann_json 3.11 CONFIG REQUIRED)
add_library(gk::json ALIAS nlohmann_json::nlohmann_json)

# ---- libyara ----------------------------------------------------------------------------------
find_package(unofficial-yara CONFIG QUIET)
if(TARGET unofficial::yara::libyara)
  add_library(gk::yara ALIAS unofficial::yara::libyara)
elseif(PKG_CONFIG_FOUND AND NOT WIN32)
  pkg_check_modules(GK_YARA REQUIRED IMPORTED_TARGET yara)
  add_library(gk::yara ALIAS PkgConfig::GK_YARA)
else()
  find_path(GK_YARA_INCLUDE_DIR yara.h REQUIRED)
  find_library(GK_YARA_LIBRARY NAMES libyara yara REQUIRED)
  add_library(gk_yara_imported UNKNOWN IMPORTED)
  set_target_properties(gk_yara_imported PROPERTIES IMPORTED_LOCATION "${GK_YARA_LIBRARY}"
                        INTERFACE_INCLUDE_DIRECTORIES "${GK_YARA_INCLUDE_DIR}")
  add_library(gk::yara ALIAS gk_yara_imported)
endif()
