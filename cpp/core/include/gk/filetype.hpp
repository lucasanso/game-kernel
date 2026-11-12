// Content-based file type identification (magic bytes first, extension second).
// Port of gamekernel/core/filetypes.py; equivalence is enforced by tests/native/test_filetype.py.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "gk/byte_view.hpp"

namespace gk {

inline constexpr std::size_t kHeaderSize = 4096;
inline constexpr std::uint64_t kIsoProbeOffset = 0x8001;
inline constexpr std::size_t kIsoProbeSize = 5;

struct TypeInfo {
    std::string kind;          // pe_exe, pe_dll, pe_sys, pe_dotnet_exe, zip, bat, text, data, ...
    std::string description;   // pt-BR
    std::string group;         // executable | script | archive | shortcut | document | data | text
    bool disguised = false;    // content contradicts a benign extension (e.g. PE named .pak)
};

struct FileTypeFilter {
    bool executables = true;
    bool libraries = true;
    bool drivers = true;
    bool scripts = true;
    bool archives = true;
    bool installers = true;
    bool java = true;
    bool shortcuts = true;
    bool data_sniffing = true;
};

// `extension` includes the dot; it is lower-cased internally (ASCII).
TypeInfo identify(ByteView header, std::string_view extension, ByteView iso_probe = {});
// Reads the header (4 KiB) and the ISO 9660 probe from disk. Throws gk::Error(FileAccess).
TypeInfo identify_file(const std::filesystem::path& path);

bool group_enabled(const TypeInfo& info, const FileTypeFilter& filter);
// Lower value = analysed first (disguised files, crack/loader executables, scripts...).
int priority(const TypeInfo& info, std::string_view file_name);

std::string lower_ascii(std::string_view text);
// Lower-case extension with dot, UTF-8 ("" when none).
std::string extension_of(const std::filesystem::path& path);

bool is_game_data_extension(std::string_view lower_ext);
bool is_executable_extension(std::string_view lower_ext);

}  // namespace gk
