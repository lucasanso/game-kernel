# Game Kernel overlay of vcpkg's ports/yara (4.6.0). Same upstream source and checksum as the official port;
# only CMakeLists.txt differs (see the header there): no OpenSSL, so no OpenSSL socket/HTTP code ends up in the
# statically linked Game Kernel binaries (checked by tests/native/test_offline_imports.py).
vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_github(
  OUT_SOURCE_PATH SOURCE_PATH
  REPO VirusTotal/yara
  REF "v${VERSION}"
  SHA512 ce8abb01d76d88e413fbbca5e977fb75250bffb26410724e76ddd874fba73bb888efd2898531bd6abf8dc963eb37a314e90c32bbc7a1bb2b1fc1bb4fa92b4773
  HEAD_REF master
  PATCHES
    # The elf module needs tlshc (not packaged); same patch as the official port.
    Disable-module-elf.patch
)

file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${SOURCE_PATH}")

vcpkg_cmake_configure(
  SOURCE_PATH "${SOURCE_PATH}"
  OPTIONS_DEBUG
    -DDISABLE_INSTALL_HEADERS=ON
    -DDISABLE_INSTALL_TOOLS=ON
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME unofficial-libyara)

vcpkg_copy_tools(TOOL_NAMES yara yarac AUTO_CLEAN)

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/COPYING")
