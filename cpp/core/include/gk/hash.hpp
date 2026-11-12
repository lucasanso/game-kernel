// Content hashes. SHA-256 (libsodium) identifies files everywhere in Game Kernel; MD5 is
// computed only for forensic cross-referencing in reports and is never used for security.
#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "gk/byte_view.hpp"
#include "gk/cancel.hpp"

namespace gk {

// Must be called once before any libsodium use (idempotent, thread-safe).
void crypto_init();

class Sha256 {
public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void update(ByteView data);
    std::array<std::uint8_t, 32> finish();

private:
    struct State;
    std::unique_ptr<State> state_;
};

class Md5 {
public:
    Md5();
    void update(ByteView data);
    std::array<std::uint8_t, 16> finish();

private:
    void block(const std::uint8_t* chunk);
    std::array<std::uint32_t, 4> h_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::uint64_t length_ = 0;
    std::size_t buffered_ = 0;
};

// SHA-1 (FIPS 180-4). Only for verifying the digests stored in legacy Authenticode signatures; never used to
// identify files.
class Sha1 {
public:
    Sha1();
    void update(ByteView data);
    std::array<std::uint8_t, 20> finish();

private:
    void block(const std::uint8_t* chunk);
    std::array<std::uint32_t, 5> h_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::uint64_t length_ = 0;
    std::size_t buffered_ = 0;
};

// SHA-512 (libsodium) and SHA-384 (the same compression function with the FIPS 180-4 SHA-384 initial values,
// truncated to 48 bytes). finish() returns 64 or 48 bytes.
class Sha512 {
public:
    explicit Sha512(bool sha384 = false);
    ~Sha512();
    Sha512(const Sha512&) = delete;
    Sha512& operator=(const Sha512&) = delete;
    void update(ByteView data);
    std::vector<std::uint8_t> finish();

private:
    struct State;
    std::unique_ptr<State> state_;
    bool sha384_;
};

std::string to_hex(std::span<const std::uint8_t> bytes);
std::string sha256_hex(ByteView data);
std::string md5_hex(ByteView data);

struct FileHashes {
    std::string sha256;
    std::string md5;   // empty when not requested
    std::uint64_t size = 0;
};

// Streaming hash of a file (1 MiB chunks). Throws gk::Error (FileAccess / Cancelled).
FileHashes hash_file(const std::filesystem::path& path, bool with_md5 = true, CancelToken* cancel = nullptr);

}  // namespace gk
