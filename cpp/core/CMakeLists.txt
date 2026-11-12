configure_file(include/gk/version.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/generated/gk/version.hpp @ONLY)
# The SQLite schema is a contract shared with Python (contracts/schema.sql): embed it, never copy it.
file(READ ${PROJECT_SOURCE_DIR}/contracts/schema.sql GK_SCHEMA_SQL)
configure_file(schema.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/generated/gk/schema.hpp @ONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/contracts/schema.sql)

add_library(gk_core STATIC
  src/file_view.cpp
  src/hash.cpp
  src/filetype.cpp
  src/text.cpp
  src/pe.cpp
  src/serialize.cpp
  src/yara_engine.cpp
  src/archive.cpp
  src/model.cpp
  src/pe_rules.cpp
  src/capabilities.cpp
  src/text_analysis.cpp
  src/analysis.cpp
  src/risk.cpp
  src/db.cpp
  src/enumerate.cpp
  src/reputation.cpp
  src/clamav.cpp
  src/authenticode.cpp
  src/authenticode_trust.cpp
  src/signature_rules.cpp
  src/quarantine.cpp
)
target_include_directories(gk_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(gk_core PUBLIC gk::json PRIVATE gk::sodium gk::yara gk::archive gk::sqlite)
if(WIN32)
  # WinVerifyTrust / catalog lookup (src/authenticode_trust.cpp); DPAPI and ACLs (src/quarantine.cpp)
  target_link_libraries(gk_core PRIVATE wintrust crypt32 advapi32)
endif()
gk_apply_options(gk_core)
