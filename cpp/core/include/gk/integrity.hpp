// Integrity of the installation (C++ counterpart of gamekernel/core/integrity.py; same files and semantics).
//
// At release time tools/build_integrity_manifest.py writes integrity_manifest.json (SHA-256 and size of every
// shipped file, data/ excluded) and signs its exact bytes with the release Ed25519 key (integrity_manifest.sig,
// 64 raw bytes). At run time:
//  * check_component(path) is called before launching a bundled binary (gk-scanworker, clamscan): a modified or
//    unlisted binary must not run;
//  * check_installation() re-hashes every listed file (dashboard, gk-cli integrity).
// Only keys shipped with the program (signatures/keys/*.pub) are trusted for the manifest. A development
// checkout has no manifest and results say so instead of claiming a verification that did not happen.
#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "gk/byte_view.hpp"
#include "gk/cancel.hpp"

namespace gk::integrity {

inline constexpr const char* kManifestName = "integrity_manifest.json";
inline constexpr const char* kSignatureName = "integrity_manifest.sig";
inline constexpr const char* kFormat = "gamekernel-integrity";

struct TrustedKey {
    std::string id;                    // first 16 hex chars of SHA-256(raw public key), as crypto_utils.key_id
    std::array<std::uint8_t, 32> raw{};
    std::string source;
};

// Ed25519 SubjectPublicKeyInfo PEM ("-----BEGIN PUBLIC KEY-----"); nullopt for anything else.
std::optional<TrustedKey> parse_public_key_pem(std::string_view pem);
// Every *.pub in the directories (missing directories ignored; invalid keys skipped and reported).
std::vector<TrustedKey> load_trusted_keys(const std::vector<std::filesystem::path>& dirs,
                                          std::vector<std::string>* problems = nullptr);
// Id of the key that signed `data`, or nullopt.
std::optional<std::string> verify_signature(ByteView data, ByteView signature, const std::vector<TrustedKey>& keys);

struct Entry {
    std::string sha256;
    std::uint64_t size = 0;
};

struct Manifest {
    bool present = false;                      // integrity_manifest.json exists
    bool valid_format = false;
    std::optional<bool> signature_valid;       // nullopt: no .sig (local build)
    std::string signer_key_id;
    std::string version;
    std::map<std::string, Entry> files;        // relative path with '/' -> entry
};

Manifest load_manifest(const std::filesystem::path& root, const std::vector<TrustedKey>& keys);

enum class ComponentStatus {
    Verified,      // listed, same size and SHA-256
    NoManifest,    // development run: nothing to verify against
    Outside,       // not inside the installation (e.g. a system tool): cannot be verified
    BadManifest,   // manifest unreadable or its signature is not from a trusted key
    NotListed,     // inside the installation but not in the manifest
    Modified,      // size or SHA-256 differs
    Unreadable,
};

struct ComponentCheck {
    ComponentStatus status = ComponentStatus::NoManifest;
    std::string message;                       // Portuguese, user-facing
    // Verified / NoManifest / Outside may be used; everything else must not run.
    [[nodiscard]] bool usable() const {
        return status == ComponentStatus::Verified || status == ComponentStatus::NoManifest ||
               status == ComponentStatus::Outside;
    }
};

struct Report {
    bool ok = false;
    bool manifest_present = false;
    std::optional<bool> signature_valid;
    std::string signer_key_id;
    std::uint64_t verified = 0;
    std::vector<std::string> missing, modified;
    std::string detail;
    double checked_at = 0;
};

// Thread-safe; the manifest is read once and component results are cached by (path, size, mtime).
class Verifier {
public:
    Verifier(std::filesystem::path root, std::vector<TrustedKey> keys);
    [[nodiscard]] const std::filesystem::path& root() const { return root_; }
    ComponentCheck check_component(const std::filesystem::path& file);
    Report check_installation(CancelToken* cancel = nullptr);   // re-reads the manifest

private:
    const Manifest& manifest();
    std::filesystem::path root_;
    std::vector<TrustedKey> keys_;
    std::mutex mutex_;
    std::optional<Manifest> manifest_;
    std::map<std::tuple<std::string, std::uint64_t, std::int64_t>, ComponentCheck> cache_;
};

std::string_view value_of(ComponentStatus s);

}  // namespace gk::integrity
