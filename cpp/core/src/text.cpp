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

std::string display_utf8(std::string_view raw, std::size_t max_bytes) {
    if (raw.size() > max_bytes) raw = raw.substr(0, max_bytes);
    std::string out;
    out.reserve(raw.size());
    std::size_t i = 0;
    auto byte = [&](std::size_t k) { return static_cast<std::uint8_t>(raw[k]); };
    while (i < raw.size()) {
        const std::uint8_t b = byte(i);
        std::uint32_t cp = 0;
        std::size_t n = 0;
        if (b < 0x80) {
            cp = b;
            n = 1;
        } else if ((b & 0xE0) == 0xC0) {
            cp = b & 0x1FU;
            n = 2;
        } else if ((b & 0xF0) == 0xE0) {
            cp = b & 0x0FU;
            n = 3;
        } else if ((b & 0xF8) == 0xF0) {
            cp = b & 0x07U;
            n = 4;
        }
        bool ok = n > 0 && i + n <= raw.size();
        for (std::size_t k = 1; ok && k < n; ++k) {
            if ((byte(i + k) & 0xC0) != 0x80) ok = false;
            cp = (cp << 6) | (byte(i + k) & 0x3FU);
        }
        static constexpr std::uint32_t kMin[] = {0, 0, 0x80, 0x800, 0x10000};
        ok = ok && cp >= kMin[n] && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);
        if (!ok) {
            append_utf8(out, 0xFFFD);
            ++i;
            continue;
        }
        const bool control = cp < 0x20 || (cp >= 0x7F && cp < 0xA0);
        const bool bidi = (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2066 && cp <= 0x2069);
        append_utf8(out, control || bidi ? 0xFFFD : cp);
        i += n;
    }
    return out;
}

std::string path_utf8(const std::filesystem::path& p) {
    const auto u8 = p.u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

std::filesystem::path utf8_path(std::string_view text) {
    return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(text.data()), text.size()));
}

}  // namespace gk::text
