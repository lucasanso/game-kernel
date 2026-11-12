configure_file(include/gk/version.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/generated/gk/version.hpp @ONLY)

add_library(gk_core STATIC
  src/file_view.cpp
  src/hash.cpp
  src/filetype.cpp
  src/text.cpp
  src/pe.cpp
  src/serialize.cpp
  src/yara_engine.cpp
)
target_include_directories(gk_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(gk_core PUBLIC gk::json PRIVATE gk::sodium gk::yara)
gk_apply_options(gk_core)
