#include "gk/hash.hpp"

#include <sodium.h>

#include <algorithm>
#include <mutex>
#include <vector>

#include "gk/error.hpp"
#include "gk/file_view.hpp"

namespace gk {

void crypto_init() {
    static std::once_flag once;
    std::call_once(once, [] {
        if (sodium_init() < 0) throw Error(ErrorCode::Internal, "falha ao inicializar libsodium");
    });
}

// ------------------------------------------------------------------ SHA-256

struct Sha256::State {
    crypto_hash_sha256_state st;
};

Sha256::Sha256() : state_(std::make_unique<State>()) {
    crypto_init();
    crypto_hash_sha256_init(&state_->st);
}

Sha256::~Sha256() {
    if (state_) sodium_memzero(&state_->st, sizeof(state_->st));
}

void Sha256::update(ByteView data) {
    if (!data.empty()) crypto_hash_sha256_update(&state_->st, data.data(), data.size());
}

std::array<std::uint8_t, 32> Sha256::finish() {
    std::array<std::uint8_t, 32> out{};
    crypto_hash_sha256_final(&state_->st, out.data());
    return out;
}

// ------------------------------------------------------------------ SHA-512 / SHA-384

struct Sha512::State {
    crypto_hash_sha512_state st;
};

Sha512::Sha512(bool sha384) : state_(std::make_unique<State>()), sha384_(sha384) {
    crypto_init();
    crypto_hash_sha512_init(&state_->st);
    if (sha384_) {
        // FIPS 180-4 §5.3.4. crypto_hash_sha512_state exposes the chaining values as part of its public API.
        static constexpr std::array<std::uint64_t, 8> kSha384Iv = {
            0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
            0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};
        std::copy(kSha384Iv.begin(), kSha384Iv.end(), std::begin(state_->st.state));
    }
}

Sha512::~Sha512() {
    if (state_) sodium_memzero(&state_->st, sizeof(state_->st));
}

void Sha512::update(ByteView data) {
    if (!data.empty()) crypto_hash_sha512_update(&state_->st, data.data(), data.size());
}

std::vector<std::uint8_t> Sha512::finish() {
    std::vector<std::uint8_t> out(crypto_hash_sha512_BYTES);
    crypto_hash_sha512_final(&state_->st, out.data());
    if (sha384_) out.resize(48);
    return out;
}

// ------------------------------------------------------------------ SHA-1 (FIPS 180-4)

namespace {
constexpr std::uint32_t rol32(std::uint32_t x, unsigned c) { return (x << c) | (x >> (32U - c)); }
}  // namespace

Sha1::Sha1() : h_{0x67452301U, 0xEFCDAB89U, 0x98BADCFEU, 0x10325476U, 0xC3D2E1F0U} {}

void Sha1::block(const std::uint8_t* chunk) {
    std::array<std::uint32_t, 80> w{};
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(chunk[4 * i]) << 24) | (static_cast<std::uint32_t>(chunk[4 * i + 1]) << 16) |
               (static_cast<std::uint32_t>(chunk[4 * i + 2]) << 8) | static_cast<std::uint32_t>(chunk[4 * i + 3]);
    }
    for (std::size_t i = 16; i < 80; ++i) w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
    for (std::size_t i = 0; i < 80; ++i) {
        std::uint32_t f = 0, k = 0;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }
        const std::uint32_t t = rol32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol32(b, 30);
        b = a;
        a = t;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
}

void Sha1::update(ByteView data) {
    const std::uint8_t* p = data.data();
    std::size_t n = data.size();
    length_ += n;
    if (buffered_ > 0) {
        const std::size_t take = std::min(n, buffer_.size() - buffered_);
        std::copy_n(p, take, buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_));
        buffered_ += take;
        p += take;
        n -= take;
        if (buffered_ == buffer_.size()) {
            block(buffer_.data());
            buffered_ = 0;
        }
    }
    while (n >= 64) {
        block(p);
        p += 64;
        n -= 64;
    }
    if (n > 0) {
        std::copy_n(p, n, buffer_.begin());
        buffered_ = n;
    }
}

std::array<std::uint8_t, 20> Sha1::finish() {
    const std::uint64_t bits = length_ * 8;
    static constexpr std::array<std::uint8_t, 64> kPad = {0x80};
    const std::size_t pad = buffered_ < 56 ? 56 - buffered_ : 120 - buffered_;
    update(ByteView(kPad.data(), pad));
    std::array<std::uint8_t, 8> len{};
    for (std::size_t i = 0; i < 8; ++i) len[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
    update(ByteView(len.data(), len.size()));
    std::array<std::uint8_t, 20> out{};
    for (std::size_t i = 0; i < 5; ++i) {
        for (std::size_t j = 0; j < 4; ++j) out[4 * i + j] = static_cast<std::uint8_t>(h_[i] >> (24 - 8 * j));
    }
    return out;
}

// ------------------------------------------------------------------ MD5 (RFC 1321)

namespace {
constexpr std::array<std::uint32_t, 64> kMd5K = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
constexpr std::array<std::uint32_t, 64> kMd5S = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                                 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                                 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                                 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

constexpr std::uint32_t rotl(std::uint32_t x, std::uint32_t c) { return (x << c) | (x >> (32 - c)); }
}  // namespace

Md5::Md5() : h_{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476} {}

void Md5::block(const std::uint8_t* chunk) {
    std::uint32_t m[16];
    for (int i = 0; i < 16; ++i) {
        m[i] = static_cast<std::uint32_t>(chunk[i * 4]) | (static_cast<std::uint32_t>(chunk[i * 4 + 1]) << 8) |
               (static_cast<std::uint32_t>(chunk[i * 4 + 2]) << 16) |
               (static_cast<std::uint32_t>(chunk[i * 4 + 3]) << 24);
    }
    std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
    for (std::uint32_t i = 0; i < 64; ++i) {
        std::uint32_t f = 0;
        std::uint32_t g = 0;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        f = f + a + kMd5K[i] + m[g];
        a = d;
        d = c;
        c = b;
        b = b + rotl(f, kMd5S[i]);
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
}

void Md5::update(ByteView data) {
    const std::uint8_t* p = data.data();
    std::size_t n = data.size();
    length_ += n;
    if (buffered_ > 0) {
        const std::size_t take = std::min(n, 64 - buffered_);
        std::copy_n(p, take, buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_));
        buffered_ += take;
        p += take;
        n -= take;
        if (buffered_ == 64) {
            block(buffer_.data());
            buffered_ = 0;
        }
    }
    while (n >= 64) {
        block(p);
        p += 64;
        n -= 64;
    }
    if (n > 0) {
        std::copy_n(p, n, buffer_.begin());
        buffered_ = n;
    }
}

std::array<std::uint8_t, 16> Md5::finish() {
    const std::uint64_t bits = length_ * 8;
    const std::uint8_t pad0 = 0x80;
    update(ByteView(&pad0, 1));
    const std::uint8_t zero = 0;
    while (buffered_ != 56) update(ByteView(&zero, 1));
    std::uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[i] = static_cast<std::uint8_t>(bits >> (8 * i));
    update(ByteView(len, 8));
    std::array<std::uint8_t, 16> out{};
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) out[static_cast<std::size_t>(i * 4 + j)] = static_cast<std::uint8_t>(h_[static_cast<std::size_t>(i)] >> (8 * j));
    }
    return out;
}

// ------------------------------------------------------------------ helpers

std::string to_hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

std::string sha256_hex(ByteView data) {
    Sha256 h;
    h.update(data);
    const auto digest = h.finish();
    return to_hex(digest);
}

std::string md5_hex(ByteView data) {
    Md5 h;
    h.update(data);
    const auto digest = h.finish();
    return to_hex(digest);
}

FileHashes hash_file(const std::filesystem::path& path, bool with_md5, CancelToken* cancel) {
    ReadOnlyFile file = ReadOnlyFile::open(path);
    Sha256 sha;
    Md5 md5;
    std::vector<std::uint8_t> buffer(1 << 20);
    FileHashes out;
    for (;;) {
        if (cancel != nullptr && !cancel->wait_if_paused()) {
            throw Error(ErrorCode::Cancelled, "hash cancelado");
        }
        const std::size_t got = file.read(buffer.data(), buffer.size());
        if (got == 0) break;
        const ByteView chunk(buffer.data(), got);
        sha.update(chunk);
        if (with_md5) md5.update(chunk);
        out.size += got;
    }
    out.sha256 = to_hex(sha.finish());
    if (with_md5) out.md5 = to_hex(md5.finish());
    return out;
}

}  // namespace gk
