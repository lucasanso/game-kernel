// Authenticode (digital signatures of PE files).
//
// Two independent layers:
//  * inspect() — portable, works on bytes (files and archive members). Walks the certificate table,
//    parses each PKCS#7 SignedData (and nested signatures) with a bounded DER reader, computes the
//    Authenticode image hash with the algorithm each signature declares and compares it with the signed
//    digest. A mismatch proves the file changed after it was signed. This layer does NOT verify the
//    cryptographic signature or the certificate chain: the signer names it reports are *claimed*.
//  * verify_trust() — Windows only. WinVerifyTrust/CryptoAPI decide whether the signature is valid and
//    chains to a trusted root, with network retrieval disabled (cache-only URL retrieval, no revocation
//    checks), plus a lookup of the system catalogs for files without an embedded signature.
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "gk/byte_view.hpp"
#include "gk/cancel.hpp"

namespace gk::authenticode {

struct Certificate {
    std::string subject_cn, subject_o, issuer_cn, issuer_o;
    std::string serial;        // hex of the INTEGER content bytes (as encoded)
    std::string sha256;        // of the DER certificate
    std::string not_before, not_after;   // ISO 8601 UTC ("2026-01-31T12:00:00Z"); empty if unparsable
    bool self_issued = false;  // subject == issuer (byte-identical names)
};

struct Signature {
    int depth = 0;                         // 0 = primary, 1.. = nested (unauthenticated attribute)
    std::string digest_algorithm;          // md5 | sha1 | sha256 | sha384 | sha512 | OID text if unknown
    std::string signed_digest;             // hex, from SpcIndirectDataContent
    std::optional<std::string> image_digest;   // hex; nullopt when the algorithm is not supported
    bool digest_matches = false;
    std::optional<Certificate> signer;     // certificate named by the SignerInfo (issuer + serial)
    std::vector<Certificate> certificates; // every certificate carried by the signature (bounded)
    bool timestamped = false;              // Authenticode countersignature or RFC 3161 token present
};

struct Report {
    bool present = false;                  // certificate table directory entry non-empty
    std::uint32_t table_offset = 0, table_size = 0;
    std::vector<Signature> signatures;     // primary signatures first, then nested ones
    std::vector<std::string> anomalies;    // structural oddities (Portuguese, user-facing)
    std::uint64_t bytes_after_table = 0;   // file bytes after the certificate table (normally 0)
    std::uint64_t hidden_bytes = 0;        // non-zero bytes inside WIN_CERTIFICATE after the PKCS#7 data
    std::optional<std::string> error;      // why the table/signature could not be parsed (malformed)

    // True when at least one signature was parsed and its declared digest differs from the image hash.
    [[nodiscard]] bool tampered() const;
    [[nodiscard]] bool parsed() const { return !signatures.empty(); }
};

struct Limits {
    std::size_t max_signatures = 8;        // primary + nested
    std::size_t max_certificates = 32;     // per signature
    std::size_t max_nesting = 2;
};

// Throws gk::Error(Cancelled) only; malformed input is reported in Report::error / anomalies.
Report inspect(ByteView file, const Limits& limits = {}, CancelToken* cancel = nullptr);

// Authenticode image hash of a PE (checksum, certificate-table directory entry and certificate table
// excluded). algorithm: md5 | sha1 | sha256 | sha384 | sha512. nullopt if not a PE or unknown algorithm.
std::optional<std::string> image_digest(ByteView file, const std::string& algorithm, CancelToken* cancel = nullptr);

enum class TrustState {
    NotChecked,        // not attempted (non-Windows build, archive member, option disabled)
    Trusted,           // valid signature chaining to a trusted root (embedded or catalog)
    Unsigned,          // no embedded signature and no catalog entry
    BadDigest,         // file modified after signing
    UntrustedRoot,     // chain ends in a root that is not trusted (e.g. self-signed)
    Expired,           // certificate expired and no timestamp
    Revoked,           // revoked according to locally cached revocation data
    Distrusted,        // certificate explicitly distrusted by Windows (Disallowed store)
    ChainIncomplete,   // chain could not be built offline (intermediate not in the local stores)
    Invalid,           // any other verification failure (bad signature, wrong usage, malformed)
};

struct TrustResult {
    TrustState state = TrustState::NotChecked;
    std::uint32_t status_code = 0;     // HRESULT returned by WinVerifyTrust
    bool from_catalog = false;
    std::string catalog;               // catalog file when from_catalog
    std::string signer, issuer;        // display names of the leaf certificate
    std::string signer_thumbprint;     // SHA-256 of the leaf certificate
    std::string timestamp;             // ISO 8601 UTC of the countersignature, if any
    std::string message;               // Portuguese, user-facing
};

std::string_view value_of(TrustState s);

// True when this build can evaluate trust (Windows).
bool trust_supported();

// Windows: WinVerifyTrust with network retrieval disabled; catalog lookup when no embedded signature.
// Other platforms: returns NotChecked with an explanatory message. Never throws for file content errors.
TrustResult verify_trust(const std::filesystem::path& file);

}  // namespace gk::authenticode
