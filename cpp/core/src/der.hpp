// Minimal, bounded DER reader for the parts of PKCS#7 / X.509 that Authenticode inspection needs.
// Every element is a view into the caller's buffer; nothing is copied or allocated while walking.
// Rejected (InvalidFormat): high tag numbers, indefinite lengths, lengths over 4 bytes or beyond the parent.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "gk/byte_view.hpp"
#include "gk/error.hpp"

namespace gk::der {

namespace tag {
inline constexpr std::uint8_t kInteger = 0x02, kBitString = 0x03, kOctetString = 0x04, kNull = 0x05, kOid = 0x06,
                              kUtf8 = 0x0C, kPrintable = 0x13, kT61 = 0x14, kIa5 = 0x16, kUtcTime = 0x17,
                              kGeneralizedTime = 0x18, kBmp = 0x1E, kUniversal = 0x1C, kSequence = 0x30, kSet = 0x31;
constexpr std::uint8_t context(unsigned n, bool constructed = true) {
    return static_cast<std::uint8_t>(0x80U | (constructed ? 0x20U : 0U) | n);
}
}  // namespace tag

struct Element {
    std::uint8_t tag = 0;
    ByteView content;   // value bytes
    ByteView encoded;   // tag + length + value
};

class Reader {
public:
    explicit Reader(ByteView data) : data_(data) {}
    [[nodiscard]] bool at_end() const { return pos_ >= data_.size(); }
    [[nodiscard]] std::size_t position() const { return pos_; }

    Element next() {
        const std::size_t start = pos_;
        const auto t = data_.u8(pos_);
        const auto first = data_.u8(pos_ + 1);
        if (!t || !first) fail("elemento truncado");
        if ((*t & 0x1FU) == 0x1FU) fail("número de tag estendido não suportado");
        std::size_t len = 0;
        std::size_t header = 2;
        if (*first < 0x80U) {
            len = *first;
        } else {
            const std::size_t n = *first & 0x7FU;
            if (n == 0) fail("comprimento indefinido (BER) não é DER");
            if (n > 4) fail("comprimento grande demais");
            for (std::size_t i = 0; i < n; ++i) {
                const auto b = data_.u8(pos_ + 2 + i);
                if (!b) fail("comprimento truncado");
                len = (len << 8) | *b;
            }
            header += n;
        }
        const auto content = data_.sub(start + header, len);
        if (!content) fail("conteúdo ultrapassa o elemento pai");
        pos_ = start + header + len;
        return {*t, *content, *data_.sub(start, header + len)};
    }

    Element expect(std::uint8_t t, const char* what) {
        const Element e = next();
        if (e.tag != t) fail(std::string("estrutura inesperada em ") + what);
        return e;
    }

    std::optional<Element> next_if(std::uint8_t t) {
        if (at_end()) return std::nullopt;
        const auto peek = data_.u8(pos_);
        if (!peek || *peek != t) return std::nullopt;
        return next();
    }

    [[noreturn]] static void fail(const std::string& why) { throw Error(ErrorCode::InvalidFormat, "DER inválido: " + why); }

private:
    ByteView data_;
    std::size_t pos_ = 0;
};

// Dotted text of an OBJECT IDENTIFIER's content ("1.2.840.113549.1.7.2"); empty if malformed.
inline std::string oid_text(ByteView content) {
    if (content.empty() || content.size() > 64) return {};
    std::string out;
    std::uint64_t value = 0;
    bool first = true;
    for (std::size_t i = 0; i < content.size(); ++i) {
        const std::uint8_t b = *content.u8(i);
        if (value > (UINT64_MAX >> 7)) return {};
        value = (value << 7) | (b & 0x7FU);
        if (b & 0x80U) continue;
        if (first) {
            const std::uint64_t a = value < 40 ? 0 : (value < 80 ? 1 : 2);
            out = std::to_string(a) + "." + std::to_string(value - 40 * a);
            first = false;
        } else {
            out += "." + std::to_string(value);
        }
        value = 0;
    }
    if (*content.u8(content.size() - 1) & 0x80U) return {};
    return out;
}

}  // namespace gk::der
