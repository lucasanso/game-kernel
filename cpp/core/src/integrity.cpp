// Installation integrity (see gk/integrity.hpp).
#include "gk/integrity.hpp"

#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cwctype>
#include <set>

#include <nlohmann/json.hpp>

#include "gk/error.hpp"
#include "gk/file_view.hpp"
#include "gk/hash.hpp"
#include "gk/text.hpp"

namespace gk::integrity {

namespace fs = std::filesystem;

namespace {

// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING }.
constexpr std::uint8_t kEd25519SpkiPrefix[12] = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
constexpr std::size_t kMaxManifest = 32U << 20;

std::string read_all(const fs::path& p, std::size_t limit) {
    const auto bytes = read_range(p, 0, limit + 1);
    if (bytes.size() > limit) throw Error(ErrorCode::ResourceLimit, "arquivo grande demais: " + text::path_utf8(p));
    return std::string(bytes.begin(), bytes.end());
}

double now_seconds() {
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

// Path of `file` relative to `root` with '/' separators; nullopt when it is not inside root.
std::optional<std::string> relative_to(const fs::path& file, const fs::path& root) {
    std::error_code ec;
    const fs::path f = fs::weakly_canonical(fs::absolute(file, ec), ec);
    if (ec) return std::nullopt;
    const fs::path r = fs::weakly_canonical(fs::absolute(root, ec), ec);
    if (ec) return std::nullopt;
    auto fi = f.begin();
    for (auto ri = r.begin(); ri != r.end(); ++ri, ++fi) {
        if (ri->empty()) continue;   // trailing separator
        if (fi == f.end()) return std::nullopt;
#ifdef _WIN32
        // Windows paths compare case-insensitively (as pathlib.WindowsPath.relative_to does).
        std::wstring a = fi->native(), b = ri->native();
        auto lower = [](wchar_t c) { return static_cast<wchar_t>(std::towlower(static_cast<std::wint_t>(c))); };
        std::transform(a.begin(), a.end(), a.begin(), lower);
        std::transform(b.begin(), b.end(), b.begin(), lower);
        if (a != b) return std::nullopt;
#else
        if (*fi != *ri) return std::nullopt;
#endif
    }
    fs::path rest;
    for (; fi != f.end(); ++fi) rest /= *fi;
    if (rest.empty()) return std::nullopt;
    const auto generic = rest.generic_u8string();   // '/' separators on every platform, as Path.as_posix()
    return std::string(reinterpret_cast<const char*>(generic.data()), generic.size());
}

}  // namespace

std::optional<TrustedKey> parse_public_key_pem(std::string_view pem) {
    constexpr std::string_view begin = "-----BEGIN PUBLIC KEY-----";
    constexpr std::string_view end = "-----END PUBLIC KEY-----";
    const auto b = pem.find(begin);
    const auto e = pem.find(end);
    if (b == std::string_view::npos || e == std::string_view::npos || e <= b) return std::nullopt;
    const std::string_view body = pem.substr(b + begin.size(), e - b - begin.size());
    crypto_init();
    std::array<std::uint8_t, 64> der{};
    std::size_t der_len = 0;
    if (sodium_base642bin(der.data(), der.size(), body.data(), body.size(), " \t\r\n", &der_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        der_len != 44 || std::memcmp(der.data(), kEd25519SpkiPrefix, sizeof kEd25519SpkiPrefix) != 0) {
        return std::nullopt;
    }
    TrustedKey key;
    std::copy(der.begin() + 12, der.begin() + 44, key.raw.begin());
    key.id = sha256_hex(ByteView(key.raw.data(), key.raw.size())).substr(0, 16);
    return key;
}

std::vector<TrustedKey> load_trusted_keys(const std::vector<fs::path>& dirs, std::vector<std::string>* problems) {
    std::vector<TrustedKey> keys;
    std::set<std::string> seen;
    for (const auto& dir : dirs) {
        std::error_code ec;
        if (!fs::is_directory(dir, ec)) continue;
        std::vector<fs::path> files;
        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (entry.is_regular_file(ec) && !entry.is_symlink(ec) && entry.path().extension() == ".pub") files.push_back(entry.path());
        }
        std::sort(files.begin(), files.end());
        for (const auto& f : files) {
            std::optional<TrustedKey> key;
            try {
                key = parse_public_key_pem(read_all(f, 4096));
            } catch (const Error&) {
                if (problems != nullptr) problems->push_back("chave ilegível: " + text::path_utf8(f));
                continue;
            }
            if (!key) {
                if (problems != nullptr) problems->push_back("não é uma chave Ed25519 válida: " + text::path_utf8(f));
                continue;
            }
            if (!seen.insert(key->id).second) continue;
            key->source = text::path_utf8(f);
            keys.push_back(std::move(*key));
        }
    }
    return keys;
}

std::optional<std::string> verify_signature(ByteView data, ByteView signature, const std::vector<TrustedKey>& keys) {
    if (signature.size() != crypto_sign_BYTES) return std::nullopt;
    crypto_init();
    for (const auto& k : keys) {
        if (crypto_sign_verify_detached(signature.data(), data.data(), data.size(), k.raw.data()) == 0) return k.id;
    }
    return std::nullopt;
}

Manifest load_manifest(const fs::path& root, const std::vector<TrustedKey>& keys) {
    Manifest m;
    std::error_code ec;
    const fs::path file = root / kManifestName;
    if (!fs::is_regular_file(file, ec)) return m;
    m.present = true;
    std::string raw;
    try {
        raw = read_all(file, kMaxManifest);
    } catch (const Error&) {
        m.signature_valid = false;
        return m;
    }
    const auto j = nlohmann::json::parse(raw, nullptr, false);
    if (j.is_discarded() || !j.is_object() || j.value("format", "") != kFormat || !j.contains("files") ||
        !j["files"].is_object()) {
        m.signature_valid = false;   // same as the Python layer: an invalid manifest counts as a bad signature
        return m;
    }
    m.valid_format = true;
    m.version = j.value("version", "");
    for (const auto& [rel, entry] : j["files"].items()) {
        if (!entry.is_object()) continue;
        m.files[rel] = Entry{entry.value("sha256", ""), entry.value("size", std::uint64_t{0})};
    }
    const fs::path sig = root / kSignatureName;
    if (fs::is_regular_file(sig, ec)) {
        std::string sig_bytes;
        try {
            sig_bytes = read_all(sig, 4096);
        } catch (const Error&) {
        }
        const auto kid = verify_signature(ByteView(raw), ByteView(sig_bytes), keys);
        m.signature_valid = kid.has_value();
        if (kid) m.signer_key_id = *kid;
    }
    return m;
}

Verifier::Verifier(fs::path root, std::vector<TrustedKey> keys) : root_(std::move(root)), keys_(std::move(keys)) {}

const Manifest& Verifier::manifest() {
    if (!manifest_) manifest_ = load_manifest(root_, keys_);
    return *manifest_;
}

ComponentCheck Verifier::check_component(const fs::path& file) {
    std::lock_guard lock(mutex_);
    const Manifest& m = manifest();
    if (!m.present) return {ComponentStatus::NoManifest, "sem manifesto de integridade (execução de desenvolvimento)"};
    if (m.signature_valid == false) {
        return {ComponentStatus::BadManifest, "manifesto de integridade inválido ou com assinatura incorreta"};
    }
    const auto rel = relative_to(file, root_);
    if (!rel) return {ComponentStatus::Outside, "componente externo à instalação (não verificável)"};
    std::error_code ec;
    const auto size = fs::file_size(file, ec);
    if (ec) return {ComponentStatus::Unreadable, "componente inacessível: " + ec.message()};
    const auto mtime = fs::last_write_time(file, ec).time_since_epoch().count();
    const auto key = std::make_tuple(text::path_utf8(fs::absolute(file)), static_cast<std::uint64_t>(size),
                                     static_cast<std::int64_t>(mtime));
    if (auto it = cache_.find(key); it != cache_.end()) return it->second;
    ComponentCheck result;
    const auto entry = m.files.find(*rel);
    if (entry == m.files.end()) {
        result = {ComponentStatus::NotListed, *rel + " não consta no manifesto de integridade"};
    } else {
        std::string digest;
        try {
            digest = hash_file(file, false).sha256;
        } catch (const Error& e) {
            return {ComponentStatus::Unreadable, std::string("componente inacessível: ") + e.what()};
        }
        if (entry->second.size != size || entry->second.sha256 != digest) {
            result = {ComponentStatus::Modified, *rel + " foi modificado desde a instalação"};
        } else {
            result = {ComponentStatus::Verified,
                      std::string("verificado") + (m.signature_valid == true ? " (manifesto assinado)" : " (manifesto sem assinatura)")};
        }
    }
    cache_[key] = result;
    return result;
}

Report Verifier::check_installation(CancelToken* cancel) {
    std::lock_guard lock(mutex_);
    manifest_.reset();
    cache_.clear();
    const Manifest& m = manifest();
    Report r;
    r.checked_at = now_seconds();
    r.manifest_present = m.present;
    r.signature_valid = m.signature_valid;
    r.signer_key_id = m.signer_key_id;
    if (!m.present) {
        r.detail = "Manifesto de integridade ausente: esta é uma execução de desenvolvimento ou a instalação está "
                   "incompleta. Os componentes não puderam ser verificados.";
        return r;
    }
    if (m.signature_valid == false) {
        r.detail = "O manifesto de integridade não possui assinatura válida de uma chave confiável.";
        return r;
    }
    for (const auto& [rel, entry] : m.files) {
        if (cancel != nullptr && !cancel->wait_if_paused()) throw Error(ErrorCode::Cancelled, "verificação cancelada");
        const fs::path full = root_ / text::utf8_path(rel);
        std::error_code ec;
        if (!fs::is_regular_file(full, ec)) {
            r.missing.push_back(rel);
            continue;
        }
        bool same = false;
        try {
            same = fs::file_size(full, ec) == entry.size && hash_file(full, false).sha256 == entry.sha256;
        } catch (const Error&) {
            same = false;
        }
        if (same) {
            ++r.verified;
        } else {
            r.modified.push_back(rel);
        }
    }
    r.ok = r.missing.empty() && r.modified.empty();
    r.detail = r.ok ? std::to_string(r.verified) + " componentes verificados" +
                          (m.signature_valid == true ? "; manifesto assinado." : "; manifesto sem assinatura (build local).")
                    : std::to_string(r.modified.size()) + " componente(s) modificado(s), " + std::to_string(r.missing.size()) +
                          " ausente(s).";
    return r;
}

std::string_view value_of(ComponentStatus s) {
    switch (s) {
        case ComponentStatus::Verified: return "verified";
        case ComponentStatus::NoManifest: return "no_manifest";
        case ComponentStatus::Outside: return "outside";
        case ComponentStatus::BadManifest: return "bad_manifest";
        case ComponentStatus::NotListed: return "not_listed";
        case ComponentStatus::Modified: return "modified";
        case ComponentStatus::Unreadable: return "unreadable";
    }
    return "unreadable";
}

}  // namespace gk::integrity
