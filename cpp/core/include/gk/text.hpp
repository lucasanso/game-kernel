// Text helpers for untrusted data: UTF-16LE decoding and printable escaping.
#pragma once

#include <cstdint>
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

// Printable representation: ASCII 0x20..0x7E kept, everything else as \xNN.
std::string escape_bytes(std::string_view raw);

}  // namespace gk::text
