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
