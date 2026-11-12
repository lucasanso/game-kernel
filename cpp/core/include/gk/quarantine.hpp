// Quarantine vault: files are moved into an encrypted, authenticated container (.gkq) and can only be
// restored after the content is proven identical to what was quarantined.
//
// Format (.gkq, version 1)
//   prefix (16 bytes): "GKQ1" | version u8 = 1 | 3 zero bytes | key id (8 bytes, SHA-256(key)[0..8))
//   libsodium crypto_secretstream_xchacha20poly1305 header (24 bytes)
//   messages: u32 LE ciphertext length | ciphertext — every message authenticated with the prefix as AD
//     content in chunks of up to 1 MiB (tag MESSAGE), then the metadata JSON (tag FINAL: original path,
//     SHA-256, size, reason — lets a lost database be rebuilt). Truncation, reordering and trailing data are
//     detected. One read pass: the content is hashed while it is encrypted.
//
// Key: 32 random bytes in <vault>/vault.key — protected with DPAPI (current user) on Windows; a 0600 file on
// other platforms (development only). Without the key the items cannot be restored.
#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "gk/cancel.hpp"
#include "gk/model.hpp"

namespace gk::db {
class Database;
}

namespace gk::quarantine {

struct Metadata {
    std::string id;                    // 32 hex chars (128 random bits)
    std::string original_path;         // UTF-8
    std::string sha256;
    std::uint64_t size = 0;
    double quarantined_at = 0;
    std::string reason, classification, detection;
    Risk risk = Risk::None;
    std::optional<std::int64_t> scan_id;
};

nlohmann::json to_json(const Metadata& m);
Metadata metadata_from_json(const nlohmann::json& j);

struct Request {
    std::filesystem::path file;
    std::optional<std::string> expected_sha256;   // refuse when the file changed since it was analysed
    std::string reason, classification, detection;
    Risk risk = Risk::None;
    std::optional<std::int64_t> scan_id;
};

class Vault;

// An item encrypted and verified in the vault while the original is still in place (and locked against
// writes on Windows). commit() deletes the original — the very file that was read, not whatever is at the
// path by then; abort() discards the vault copy. Destroying an uncommitted Pending aborts it.
class Pending {
public:
    Pending(Pending&&) noexcept;
    Pending& operator=(Pending&&) = delete;
    ~Pending();
    [[nodiscard]] const Metadata& metadata() const { return meta_; }
    void commit();
    void abort() noexcept;

private:
    friend class Vault;
    struct Source;
    Pending(Vault& vault, Metadata meta, std::unique_ptr<Source> source);
    Vault* vault_;
    Metadata meta_;
    std::unique_ptr<Source> source_;
    bool done_ = false;
};

struct VerifyReport {
    std::vector<std::string> ok;                               // ids authenticated end to end
    std::vector<std::pair<std::string, std::string>> damaged;  // id, reason
    std::vector<Metadata> unknown;                             // valid .gkq files not listed by the caller
};

class Vault {
public:
    // Creates the folder (protected ACL on Windows: SYSTEM, Administrators and the current user only) and
    // loads or creates the key.
    static std::unique_ptr<Vault> open(const std::filesystem::path& folder);
    ~Vault();
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    [[nodiscard]] const std::filesystem::path& dir() const { return dir_; }
    [[nodiscard]] std::filesystem::path item_path(const std::string& id) const;
    [[nodiscard]] std::string key_id() const;
    // Non-fatal problems found when opening (e.g. the file system does not support access control lists).
    [[nodiscard]] const std::vector<std::string>& warnings() const { return warnings_; }

    // Reads, hashes and encrypts the file in one pass, then decrypts the stored copy end to end before
    // returning. Throws gk::Error (FileAccess: unreadable, in use or not a regular file; InvalidRequest:
    // content differs from expected_sha256; Cancelled).
    Pending prepare(const Request& request, CancelToken* cancel = nullptr);

    // Authenticates the item and writes it to `destination` through a temporary file in the same folder,
    // renamed only after size and SHA-256 match the metadata (and `expected_sha256`, when given).
    // Refuses an existing destination unless `overwrite`. Does not delete the vault copy.
    Metadata restore(const std::string& id, const std::filesystem::path& destination, bool overwrite,
                     const std::optional<std::string>& expected_sha256 = std::nullopt, CancelToken* cancel = nullptr);

    // Authenticates the whole item without writing anything; returns its metadata.
    Metadata inspect(const std::string& id, CancelToken* cancel = nullptr);

    void erase(const std::string& id);

    // Authenticates every item; ids in `known` are expected, other valid .gkq files are reported as unknown.
    VerifyReport verify(const std::vector<std::string>& known, CancelToken* cancel = nullptr);

private:
    friend class Pending;
    explicit Vault(std::filesystem::path folder);
    std::filesystem::path dir_;
    std::array<std::uint8_t, 32> key_{};
    std::array<std::uint8_t, 8> key_id_{};
    std::vector<std::string> warnings_;
};

// Vault + database + audit log: what the application and gk-cli use.
class Manager {
public:
    Manager(Vault& vault, db::Database& database) : vault_(vault), db_(database) {}
    Metadata quarantine(const Request& request, CancelToken* cancel = nullptr);
    std::filesystem::path restore(const std::string& id, const std::optional<std::filesystem::path>& destination,
                                  bool overwrite, CancelToken* cancel = nullptr);
    void erase(const std::string& id);
    // Authenticates the items listed as quarantined; valid unknown items (database lost or rolled back) are
    // registered again from their encrypted metadata.
    VerifyReport verify(CancelToken* cancel = nullptr);

private:
    Vault& vault_;
    db::Database& db_;
};

}  // namespace gk::quarantine
