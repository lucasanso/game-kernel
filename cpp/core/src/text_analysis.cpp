// Network literals (IPv4:port), Windows shortcut (.lnk) parsing and script text helpers.
#include <algorithm>
#include <array>
#include <cctype>
#include <string>

#include "gk/analysis.hpp"
#include "gk/filetype.hpp"
#include "gk/text.hpp"

namespace gk::analysis {

namespace {

// Reads ASCII characters either from consecutive bytes (stride 1) or UTF-16LE code units (stride 2,
// high byte must be 0).
struct Narrow {
    ByteView d;
    std::size_t stride;
    [[nodiscard]] std::size_t size() const { return d.size() / stride; }
    [[nodiscard]] int at(std::size_t i) const {
        const std::size_t pos = i * stride;
        if (pos + stride > d.size()) return -1;
        if (stride == 2 && d.data()[pos + 1] != 0) return -1;
        return d.data()[pos];
    }
};

bool is_digit(int c) { return c >= '0' && c <= '9'; }

// Parse up to 3 digits <= 255 starting at i; returns digits consumed (0 when invalid).
std::size_t octet(const Narrow& n, std::size_t i, int& value) {
    std::size_t k = 0;
    value = 0;
    while (k < 3 && is_digit(n.at(i + k))) {
        value = value * 10 + (n.at(i + k) - '0');
        ++k;
    }
    if (k == 0 || value > 255 || is_digit(n.at(i + k))) return 0;
    return k;
}

void scan(const Narrow& n, std::vector<Location>& out, std::size_t max_hits) {
    const std::size_t size = n.size();
    for (std::size_t i = 0; i < size && out.size() < max_hits; ++i) {
        if (!is_digit(n.at(i))) continue;
        if (i > 0 && (is_digit(n.at(i - 1)) || n.at(i - 1) == '.')) continue;
        std::size_t p = i;
        int oct[4] = {0, 0, 0, 0};
        bool ok = true;
        for (int k = 0; k < 4 && ok; ++k) {
            const std::size_t used = octet(n, p, oct[k]);
            if (used == 0) {
                ok = false;
                break;
            }
            p += used;
            if (k < 3) {
                if (n.at(p) != '.') ok = false;
                ++p;
            }
        }
        if (!ok || n.at(p) != ':') continue;
        ++p;
        std::size_t digits = 0;
        unsigned port = 0;
        while (digits < 6 && is_digit(n.at(p + digits))) {
            port = port * 10 + static_cast<unsigned>(n.at(p + digits) - '0');
            ++digits;
        }
        if (digits < 2 || digits > 5 || port == 0 || port > 65535 || is_digit(n.at(p + digits))) continue;
        if (oct[0] == 0 || oct[0] == 127 || (oct[0] == 255 && oct[1] == 255)) continue;  // unspecified/loopback/broadcast
        std::string text = std::to_string(oct[0]) + "." + std::to_string(oct[1]) + "." + std::to_string(oct[2]) + "." +
                           std::to_string(oct[3]) + ":" + std::to_string(port);
        Location l;
        l.kind = "string";
        l.description = n.stride == 2 ? "endereço IP:porta (UTF-16)" : "endereço IP:porta";
        l.offset = i * n.stride;
        l.length = static_cast<std::uint32_t>((p + digits - i) * n.stride);
        l.excerpt = text;
        out.push_back(std::move(l));
        i = p + digits;
    }
}

std::string read_lnk_string(ByteView d, std::size_t& pos, bool unicode) {
    auto count = d.le<std::uint16_t>(pos);
    if (!count) {
        pos = d.size();
        return {};
    }
    pos += 2;
    std::string out;
    if (unicode) {
        std::size_t consumed = 0;
        out = text::utf16le_to_utf8(d.clamp(pos, static_cast<std::size_t>(*count) * 2), *count, &consumed);
        pos += static_cast<std::size_t>(*count) * 2;
    } else {
        const ByteView raw = d.clamp(pos, *count);
        for (std::size_t i = 0; i < raw.size(); ++i) text::append_utf8(out, raw.data()[i]);
        pos += *count;
    }
    return out;
}

int b64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

std::string b64_decode(std::string_view s) {
    std::string out;
    unsigned acc = 0;
    int bits = 0;
    for (char ch : s) {
        if (ch == '=') break;
        const int v = b64_value(static_cast<unsigned char>(ch));
        if (v < 0) return {};
        acc = (acc << 6) | static_cast<unsigned>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFF));
        }
    }
    return out;
}

bool is_b64_char(unsigned char c) { return b64_value(c) >= 0 || c == '='; }

// UTF-16LE text that is mostly printable ASCII -> UTF-8; empty when it does not look like text.
std::string utf16_text(const std::string& raw) {
    if (raw.size() < 4 || raw.size() % 2 != 0) return {};
    std::size_t printable = 0;
    for (std::size_t i = 0; i + 1 < raw.size(); i += 2) {
        const auto lo = static_cast<unsigned char>(raw[i]);
        const auto hi = static_cast<unsigned char>(raw[i + 1]);
        if (hi == 0 && (lo >= 0x20 || lo == '\n' || lo == '\r' || lo == '\t')) ++printable;
    }
    if (printable * 10 < (raw.size() / 2) * 8) return {};
    return text::utf16le_to_utf8(ByteView(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size()), raw.size() / 2);
}

bool printable_utf8(const std::string& raw) {
    if (raw.size() < 8) return false;
    std::size_t printable = 0;
    for (unsigned char c : raw) printable += (c >= 0x20 || c == '\n' || c == '\r' || c == '\t') ? 1 : 0;
    return printable * 10 >= raw.size() * 9;
}

std::uint32_t line_of(const std::string& text, std::size_t pos) {
    return static_cast<std::uint32_t>(1 + std::count(text.begin(), text.begin() + static_cast<std::ptrdiff_t>(std::min(pos, text.size())), '\n'));
}

}  // namespace

std::vector<Location> network_literals(ByteView data, std::size_t max_hits) {
    std::vector<Location> out;
    scan(Narrow{data, 1}, out, max_hits);
    if (out.size() < max_hits) scan(Narrow{data, 2}, out, max_hits);
    if (data.size() > 1 && out.size() < max_hits) scan(Narrow{data.clamp(1, data.size()), 2}, out, max_hits);
    return out;
}

LnkInfo parse_lnk(ByteView d) {
    LnkInfo info;
    if (!d.starts_with(std::string_view("L\x00\x00\x00\x01\x14\x02\x00", 8)) || d.size() < 76) return info;
    const std::uint32_t flags = *d.le<std::uint32_t>(0x14);
    std::size_t pos = 76;
    if (flags & 0x1) {  // HasLinkTargetIDList
        auto id_size = d.le<std::uint16_t>(pos);
        if (!id_size) return info;
        pos += 2 + *id_size;
    }
    if (flags & 0x2) {  // HasLinkInfo
        auto size = d.le<std::uint32_t>(pos);
        if (!size || *size < 28) return info;
        const ByteView li = d.clamp(pos, *size);
        if (auto base_off = li.le<std::uint32_t>(16); base_off && *base_off != 0) {
            info.target = text::c_string(li, *base_off, 1024);
        }
        if (auto header = li.le<std::uint32_t>(4); header && *header >= 0x24) {
            if (auto ubase = li.le<std::uint32_t>(28); ubase && *ubase != 0) {
                info.target = text::utf16le_to_utf8(li.clamp(*ubase, 2048), 1024);
            }
        }
        pos += *size;
    }
    const bool unicode = (flags & 0x80) != 0;
    if (flags & 0x04) info.name = read_lnk_string(d, pos, unicode);
    if (flags & 0x08) {
        const std::string rel = read_lnk_string(d, pos, unicode);
        if (info.target.empty()) info.target = rel;
    }
    if (flags & 0x10) info.working_dir = read_lnk_string(d, pos, unicode);
    if (flags & 0x20) info.arguments = read_lnk_string(d, pos, unicode);
    if (flags & 0x40) info.icon_location = read_lnk_string(d, pos, unicode);
    info.valid = true;
    return info;
}

std::string script_text(ByteView data, std::size_t max_bytes) {
    const ByteView d = data.prefix(max_bytes);
    if (d.starts_with("\xef\xbb\xbf")) return d.clamp(3, d.size()).to_string();
    if (d.starts_with("\xff\xfe")) return text::utf16le_to_utf8(d.clamp(2, d.size()), d.size() / 2);
    if (d.starts_with("\xfe\xff")) {
        std::string swapped(d.size() - 2, '\0');
        for (std::size_t i = 2; i + 1 < d.size(); i += 2) {
            swapped[i - 2] = static_cast<char>(d.data()[i + 1]);
            swapped[i - 1] = static_cast<char>(d.data()[i]);
        }
        return text::utf16le_to_utf8(ByteView(swapped), swapped.size() / 2);
    }
    // UTF-16LE without BOM: every second byte zero in the first bytes.
    if (d.size() >= 8) {
        std::size_t zeros = 0;
        const std::size_t probe = std::min<std::size_t>(d.size(), 200) & ~static_cast<std::size_t>(1);
        for (std::size_t i = 1; i < probe; i += 2) zeros += d.data()[i] == 0 ? 1 : 0;
        if (zeros * 10 >= (probe / 2) * 9) return text::utf16le_to_utf8(d, d.size() / 2);
    }
    return d.to_string();
}

std::vector<DecodedPayload> decode_script_payloads(const std::string& text) {
    std::vector<DecodedPayload> out;
    const std::string lower = lower_ascii(text);
    static constexpr std::string_view kEncoded = "encodedcommand";
    // -e / -ec / -en / -enc ... / -EncodedCommand (any prefix PowerShell accepts), also with '/'.
    for (std::size_t i = 0; i + 3 < lower.size() && out.size() < 16; ++i) {
        if ((lower[i] != '-' && lower[i] != '/') || lower[i + 1] != 'e') continue;
        if (i > 0 && std::isalnum(static_cast<unsigned char>(lower[i - 1]))) continue;
        std::size_t j = i + 1;
        while (j < lower.size() && std::isalpha(static_cast<unsigned char>(lower[j]))) ++j;
        const std::string_view word(lower.data() + i + 1, j - i - 1);
        if (!(word == "ec" || kEncoded.substr(0, word.size()) == word)) continue;
        std::size_t k = j;
        while (k < text.size() && (text[k] == ' ' || text[k] == '\t' || text[k] == '"' || text[k] == '\'')) ++k;
        std::size_t e = k;
        while (e < text.size() && is_b64_char(static_cast<unsigned char>(text[e]))) ++e;
        if (e - k < 16) continue;
        const std::string decoded = b64_decode(std::string_view(text).substr(k, e - k));
        const std::string as_text = utf16_text(decoded);
        if (as_text.empty()) continue;
        out.push_back(DecodedPayload{line_of(text, i), "encoded_command", as_text, false});
        i = e;
    }
    static constexpr std::string_view kFrom = "frombase64string(";
    for (std::size_t i = lower.find(kFrom); i != std::string::npos && out.size() < 32; i = lower.find(kFrom, i + 1)) {
        std::size_t k = i + kFrom.size();
        while (k < text.size() && (text[k] == ' ' || text[k] == '"' || text[k] == '\'')) ++k;
        std::size_t e = k;
        while (e < text.size() && is_b64_char(static_cast<unsigned char>(text[e]))) ++e;
        if (e - k < 40) continue;
        const std::string decoded = b64_decode(std::string_view(text).substr(k, e - k));
        DecodedPayload p{line_of(text, i), "base64_blob", {}, false};
        if (decoded.size() >= 2 && decoded[0] == 'M' && decoded[1] == 'Z') {
            p.is_pe = true;
        } else if (std::string t = utf16_text(decoded); !t.empty()) {
            p.text = std::move(t);
        } else if (printable_utf8(decoded)) {
            p.text = decoded;
        } else {
            continue;
        }
        out.push_back(std::move(p));
    }
    return out;
}

}  // namespace gk::analysis
