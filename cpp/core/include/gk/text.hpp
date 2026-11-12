// Text helpers for untrusted data: UTF-16LE decoding and printable escaping.
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "gk/byte_view.hpp"

namespace gk::text {

// Decode UTF-16LE (code units up to the first NUL or `max_units`); invalid sequences -> U+FFFD.
// `consumed` receives the number of bytes read including the terminating NUL when present.
std::string utf16le_to_utf8(ByteView data, std::size_t max_units, std::size_t* consumed = nullptr);

// Append one code point as UTF-8.
void append_utf8(std::string& out, std::uint32_t code_point);

// ASCII C string at `offset` (stops at NUL or after `max_len`). `terminated` tells whether a NUL was found.
std::string c_string(ByteView data, std::size_t offset, std::size_t max_len, bool* terminated = nullptr);

// UTF-8 for display of untrusted names (certificate subjects, resources): invalid sequences, C0/C1 control
// characters and bidirectional overrides/isolates (U+202A..U+202E, U+2066..U+2069, used to spoof names) become
// U+FFFD. At most `max_bytes` of input are read.
std::string display_utf8(std::string_view raw, std::size_t max_bytes = 4096);

// UTF-8 text of a path on every platform. Never use path::string() for display or keys: on Windows it
// converts through the ANSI code page and throws or mangles names outside it.
std::string path_utf8(const std::filesystem::path& p);
// Inverse of path_utf8 (UTF-8 text stored in the database or JSON back to a native path).
std::filesystem::path utf8_path(std::string_view text);

// Printable representation: ASCII 0x20..0x7E kept, everything else as \xNN.
std::string escape_bytes(std::string_view raw);

}  // namespace gk::text
