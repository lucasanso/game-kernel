#include "gk/text.hpp"

namespace gk::text {

void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) cp = 0xFFFD;
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::string utf16le_to_utf8(ByteView data, std::size_t max_units, std::size_t* consumed) {
    std::string out;
    std::size_t pos = 0;
    std::size_t units = 0;
    bool terminated = false;
    while (units < max_units) {
        auto unit = data.le<std::uint16_t>(pos);
        if (!unit) break;
        pos += 2;
        ++units;
        if (*unit == 0) {
            terminated = true;
            break;
        }
        std::uint32_t cp = *unit;
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            auto low = data.le<std::uint16_t>(pos);
            if (low && *low >= 0xDC00 && *low <= 0xDFFF && units < max_units) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (*low - 0xDC00);
                pos += 2;
                ++units;
            } else {
                cp = 0xFFFD;
            }
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
        append_utf8(out, cp);
    }
    (void)terminated;
    if (consumed != nullptr) *consumed = pos;
    return out;
}

std::string c_string(ByteView data, std::size_t offset, std::size_t max_len, bool* terminated) {
    std::string out;
    bool found = false;
    for (std::size_t i = 0; i < max_len; ++i) {
        auto b = data.u8(offset + i);
        if (!b) break;
        if (*b == 0) {
            found = true;
            break;
        }
        out.push_back(static_cast<char>(*b));
    }
    if (terminated != nullptr) *terminated = found;
    return out;
}

std::string escape_bytes(std::string_view raw) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size());
    for (char ch : raw) {
        const auto b = static_cast<std::uint8_t>(ch);
        if (b >= 0x20 && b < 0x7F && b != '\\') {
            out.push_back(ch);
        } else {
            out += "\\x";
            out.push_back(kHex[b >> 4]);
            out.push_back(kHex[b & 0x0F]);
        }
    }
    return out;
}

}  // namespace gk::text
