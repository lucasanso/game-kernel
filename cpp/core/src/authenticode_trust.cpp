// Trust evaluation of Authenticode signatures (Windows). See gk/authenticode.hpp.
//
// Offline by construction: WTD_CACHE_ONLY_URL_RETRIEVAL forbids CryptoAPI from fetching anything (AIA
// intermediates, CRLs, OCSP, root updates); revocation checks are disabled (WTD_REVOKE_NONE +
// WTD_REVOCATION_CHECK_NONE). Only certificates, catalogs and revocation data already on the machine count.
#include "gk/authenticode.hpp"

#include <cstdio>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00   // CryptCATAdminAcquireContext2 / CalcHashFromFileHandle2 need Windows 8+
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// windows.h must come first.
#include <bcrypt.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>

#ifndef WTD_DISABLE_MD2_MD4   // Windows SDK value; missing from some MinGW headers
#define WTD_DISABLE_MD2_MD4 0x00002000
#endif

#include <vector>

#include "gk/hash.hpp"
#endif

namespace gk::authenticode {

#ifdef _WIN32

namespace {

std::string hex32(std::uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%08X", v);
    return buf;
}

std::string message_for(TrustState s, const std::string& signer, bool catalog, std::uint32_t code) {
    switch (s) {
        case TrustState::Trusted:
            return "Assinatura válida de " + (signer.empty() ? std::string("assinante sem nome") : signer) +
                   (catalog ? " (catálogo do sistema)" : "") + ", verificada pelo Windows sem consulta à rede.";
        case TrustState::Unsigned:
            return "Sem assinatura digital (nem embutida, nem em catálogo do sistema).";
        case TrustState::BadDigest:
            return "O conteúdo não corresponde à assinatura: o arquivo foi alterado depois de assinado.";
        case TrustState::UntrustedRoot:
            return "A cadeia do certificado termina em uma raiz não confiável (por exemplo, certificado autoassinado).";
        case TrustState::Expired:
            return "O certificado expirou e a assinatura não tem carimbo de tempo.";
        case TrustState::Revoked:
            return "O certificado foi revogado, segundo dados de revogação já presentes no computador.";
        case TrustState::Distrusted:
            return "O certificado está explicitamente bloqueado pelo Windows (repositório de certificados não confiáveis).";
        case TrustState::ChainIncomplete:
            return "Não foi possível montar a cadeia de certificados sem acesso à rede; a assinatura não pôde ser confirmada.";
        case TrustState::Invalid:
            return "Assinatura inválida (código " + hex32(code) + ").";
        case TrustState::NotChecked:
            break;
    }
    return "A confiança da assinatura não foi verificada.";
}

std::string narrow(const wchar_t* w) {
    if (w == nullptr || *w == L'\0') return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<std::size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::string cert_name(PCCERT_CONTEXT cert, DWORD flags) {
    const DWORD n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, nullptr, 0);
    if (n <= 1) return {};
    std::wstring buf(n, L'\0');
    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, buf.data(), n);
    return narrow(buf.c_str());
}

std::string filetime_iso(const FILETIME& ft) {
    SYSTEMTIME st{};
    if ((ft.dwHighDateTime == 0 && ft.dwLowDateTime == 0) || !FileTimeToSystemTime(&ft, &st)) return {};
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04u-%02u-%02uT%02u:%02u:%02uZ", st.wYear, st.wMonth, st.wDay, st.wHour,
                  st.wMinute, st.wSecond);
    return buf;
}

TrustState state_of(LONG status) {
    switch (static_cast<HRESULT>(status)) {
        case ERROR_SUCCESS: return TrustState::Trusted;
        case TRUST_E_NOSIGNATURE:
        case TRUST_E_SUBJECT_FORM_UNKNOWN:
        case TRUST_E_PROVIDER_UNKNOWN: return TrustState::Unsigned;
        case TRUST_E_BAD_DIGEST: return TrustState::BadDigest;
        case CERT_E_UNTRUSTEDROOT:
        case CERT_E_UNTRUSTEDTESTROOT: return TrustState::UntrustedRoot;
        case CERT_E_EXPIRED: return TrustState::Expired;
        case CERT_E_REVOKED:
        case CRYPT_E_REVOKED: return TrustState::Revoked;
        case TRUST_E_EXPLICIT_DISTRUST: return TrustState::Distrusted;
        case CERT_E_CHAINING:
        case CERT_E_REVOCATION_FAILURE:
        case CRYPT_E_REVOCATION_OFFLINE: return TrustState::ChainIncomplete;
        default: return TrustState::Invalid;
    }
}

// Runs WinVerifyTrust on a prepared WINTRUST_DATA, collects the signer and always closes the state.
TrustResult run(WINTRUST_DATA& data) {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4;
    const HWND no_ui = static_cast<HWND>(INVALID_HANDLE_VALUE);
    const LONG status = WinVerifyTrust(no_ui, &action, &data);

    TrustResult r;
    r.status_code = static_cast<std::uint32_t>(status);
    r.state = state_of(status);
    if (data.hWVTStateData != nullptr) {
        if (CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(data.hWVTStateData)) {
            if (CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0)) {
                if (sgnr->csCertChain > 0 && sgnr->pasCertChain != nullptr && sgnr->pasCertChain[0].pCert != nullptr) {
                    PCCERT_CONTEXT leaf = sgnr->pasCertChain[0].pCert;
                    r.signer = cert_name(leaf, 0);
                    r.issuer = cert_name(leaf, CERT_NAME_ISSUER_FLAG);
                    r.signer_thumbprint = sha256_hex(ByteView(leaf->pbCertEncoded, leaf->cbCertEncoded));
                }
                if (sgnr->csCounterSigners > 0) r.timestamp = filetime_iso(sgnr->sftVerifyAsOf);
            }
        }
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(no_ui, &action, &data);
    return r;
}

// System catalogs (most Windows components are signed this way, not with an embedded signature).
std::optional<TrustResult> verify_catalog(const std::filesystem::path& file, HANDLE handle) {
    for (const wchar_t* algorithm : {BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA1_ALGORITHM}) {
        GUID driver_action = DRIVER_ACTION_VERIFY;
        HCATADMIN admin = nullptr;
        if (!CryptCATAdminAcquireContext2(&admin, &driver_action, algorithm, nullptr, 0)) continue;
        DWORD size = 0;
        SetFilePointer(handle, 0, nullptr, FILE_BEGIN);
        CryptCATAdminCalcHashFromFileHandle2(admin, handle, &size, nullptr, 0);
        std::vector<BYTE> hash(size);
        SetFilePointer(handle, 0, nullptr, FILE_BEGIN);
        if (size == 0 || !CryptCATAdminCalcHashFromFileHandle2(admin, handle, &size, hash.data(), 0)) {
            CryptCATAdminReleaseContext(admin, 0);
            continue;
        }
        HCATINFO cat = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), size, 0, nullptr);
        if (cat == nullptr) {
            CryptCATAdminReleaseContext(admin, 0);
            continue;
        }
        CATALOG_INFO info{};
        info.cbStruct = sizeof(info);
        std::optional<TrustResult> result;
        if (CryptCATCatalogInfoFromContext(cat, &info, 0)) {
            std::wstring tag;
            static constexpr wchar_t kHex[] = L"0123456789ABCDEF";
            for (BYTE b : hash) {
                tag.push_back(kHex[b >> 4]);
                tag.push_back(kHex[b & 0xF]);
            }
            WINTRUST_CATALOG_INFO ci{};
            ci.cbStruct = sizeof(ci);
            ci.pcwszCatalogFilePath = info.wszCatalogFile;
            ci.pcwszMemberFilePath = file.c_str();
            ci.pcwszMemberTag = tag.c_str();
            ci.hMemberFile = handle;
            ci.pbCalculatedFileHash = hash.data();
            ci.cbCalculatedFileHash = size;
            ci.hCatAdmin = admin;
            WINTRUST_DATA data{};
            data.dwUnionChoice = WTD_CHOICE_CATALOG;
            data.pCatalog = &ci;
            result = run(data);
            result->from_catalog = true;
            result->catalog = narrow(info.wszCatalogFile);
        }
        CryptCATAdminReleaseCatalogContext(admin, cat, 0);
        CryptCATAdminReleaseContext(admin, 0);
        if (result) return result;
    }
    return std::nullopt;
}

}  // namespace

bool trust_supported() { return true; }

TrustResult verify_trust(const std::filesystem::path& file) {
    HANDLE handle = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        TrustResult r;
        r.status_code = GetLastError();
        r.message = "Não foi possível abrir o arquivo para verificar a assinatura (erro do Windows " +
                    std::to_string(r.status_code) + ").";
        return r;
    }
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = file.c_str();
    fi.hFile = handle;
    WINTRUST_DATA data{};
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fi;
    TrustResult r = run(data);
    if (r.state == TrustState::Unsigned) {
        if (auto catalog = verify_catalog(file, handle)) r = std::move(*catalog);
    }
    CloseHandle(handle);
    r.message = message_for(r.state, r.signer, r.from_catalog, r.status_code);
    return r;
}

#else

bool trust_supported() { return false; }

TrustResult verify_trust(const std::filesystem::path&) {
    TrustResult r;
    r.message = "A cadeia de confiança das assinaturas só é verificada no Windows (WinVerifyTrust).";
    return r;
}

#endif

}  // namespace gk::authenticode
