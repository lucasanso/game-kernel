// .gkpkg v1 verifier (C++ side). The format is specified in gamekernel/updates/package.py and
// docs/OFFLINE_UPDATES.md; the Python reference verifier and this one must reach the same
// decision (and error code) for every input — tests/updates/test_equivalence.py checks that.
//
// Security model: nothing in a package is trusted before the Ed25519 signature over
// magic || manifest_len || manifest has been verified against a locally trusted key. Payloads
// are then authenticated by the SHA-256 values inside the signed manifest, in one streaming pass.
#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <array>
#include <functional>
#include <optional>
#include <vector>

namespace gk::updates {

inline constexpr char kMagic[8] = {'G', 'K', 'P', 'K', 'G', '\0', '\x01', '\0'};
inline constexpr int kFormatVersion = 1;
inline constexpr quint32 kSigLen = 64;
inline constexpr qint64 kMaxManifest = 1024 * 1024;
inline constexpr int kMaxFiles = 512;
inline constexpr qint64 kMaxFileSize = qint64(1024) * 1024 * 1024;
inline constexpr qint64 kMaxTotal = qint64(4) * 1024 * 1024 * 1024;

// Stable error codes (same strings as gamekernel.updates.package.PackageError.code).
namespace error_code {
inline constexpr const char* NotAPackage = "not_a_package";
inline constexpr const char* UnsupportedFormat = "unsupported_format";
inline constexpr const char* InvalidHeader = "invalid_header";
inline constexpr const char* Truncated = "truncated";
inline constexpr const char* NoTrustedKeys = "no_trusted_keys";
inline constexpr const char* BadSignature = "bad_signature";
inline constexpr const char* InvalidManifest = "invalid_manifest";
inline constexpr const char* IncompatibleApp = "incompatible_app";
inline constexpr const char* HashMismatch = "hash_mismatch";
inline constexpr const char* TrailingData = "trailing_data";
inline constexpr const char* Downgrade = "downgrade";
inline constexpr const char* ValidationFailed = "validation_failed";
inline constexpr const char* IoError = "io_error";
inline constexpr const char* Busy = "busy";
}  // namespace error_code

struct Error {
    QString code;
    QString message;
};

struct TrustedKey {
    QString id;                 // first 16 hex chars of SHA-256(raw public key)
    std::array<unsigned char, 32> raw{};
    QString source;             // file it was loaded from
};

// Parses an Ed25519 SubjectPublicKeyInfo PEM ("-----BEGIN PUBLIC KEY-----").
std::optional<TrustedKey> parsePublicKeyPem(const QByteArray& pem, const QString& source = {});
QString keyIdOf(const std::array<unsigned char, 32>& raw);
// Loads every *.pub from the directories (missing directories are ignored; invalid keys are skipped
// and reported in `problems`).
std::vector<TrustedKey> loadTrustedKeys(const QStringList& directories, QStringList* problems = nullptr);

struct FileEntry {
    QString path;               // "<component>/<name>"
    QString component;
    QString name;
    qint64 size = 0;
    QByteArray sha256Hex;       // lowercase hex
};

struct Manifest {
    QJsonObject json;           // full manifest as signed
    QString packageId;
    QString packageVersion;
    QString publisher;
    QString minAppVersion;
    QString signingKeyId;
    QJsonObject components;
    std::vector<FileEntry> files;
};

// Version helpers. Package versions: YYYY.M.D[.N]; application versions: X.Y.Z.
std::optional<std::array<int, 4>> parsePackageVersion(const QString& v);
std::optional<std::array<int, 3>> parseAppVersion(const QString& v);

// Structural validation of a manifest (no signature, no app compatibility). Empty list = valid.
QStringList validateManifest(const QJsonObject& manifest, Manifest* parsed = nullptr);

struct VerifyResult {
    bool ok = false;
    Error error;
    QString keyId;              // trusted key that signed the package
    Manifest manifest;
};

// Called for each payload chunk during the streaming pass (for extraction). Return false to abort.
using PayloadSink = std::function<bool(const FileEntry& file, const char* data, qint64 size, bool last)>;

// Full verification: header, signature, manifest, app compatibility, every payload hash, no trailing
// data. With a sink, payload bytes are handed over while being hashed (single pass, no TOCTOU).
VerifyResult verifyPackage(const QString& packagePath, const std::vector<TrustedKey>& keys,
                           const QString& appVersion, const PayloadSink& sink = {});

}  // namespace gk::updates
