// Quarantine vault (see gk/quarantine.hpp for the .gkq format).
#include "gk/quarantine.hpp"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <ctime>
#include <set>

#include "gk/db.hpp"
#include "gk/error.hpp"
#include "gk/file_view.hpp"
#include "gk/hash.hpp"
#include "gk/text.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// windows.h first
#include <aclapi.h>
#include <dpapi.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace gk::quarantine {

namespace fs = std::filesystem;
using nlohmann::json;

namespace {

constexpr std::size_t kChunk = 1U << 20;
constexpr std::size_t kMaxMetadata = 64U << 10;
constexpr std::size_t kPrefixSize = 16;
constexpr std::uint8_t kFormatVersion = 1;
constexpr std::size_t kABytes = crypto_secretstream_xchacha20poly1305_ABYTES;
constexpr std::size_t kHeaderBytes = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
static_assert(crypto_secretstream_xchacha20poly1305_KEYBYTES == 32);

double now_seconds() {
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void check_cancel(CancelToken* cancel) {
    if (cancel != nullptr && !cancel->wait_if_paused()) throw Error(ErrorCode::Cancelled, "operação cancelada");
}

bool valid_id(const std::string& id) {
    return id.size() == 32 && std::all_of(id.begin(), id.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

std::string random_id() {
    std::array<std::uint8_t, 16> raw{};
    randombytes_buf(raw.data(), raw.size());
    return to_hex(raw);
}

std::string display(const fs::path& p) { return text::path_utf8(p); }

std::string lower_hex(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// ------------------------------------------------------------------ files written by the vault

class OutFile {
public:
    // Creates a new file (fails if it exists); owner-only permissions on POSIX.
    explicit OutFile(const fs::path& path) : path_(path) {
#ifdef _WIN32
        h_ = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h_ == INVALID_HANDLE_VALUE) {
            throw Error(ErrorCode::FileAccess, "não foi possível criar " + display(path) + " (erro do Windows " +
                                                   std::to_string(GetLastError()) + ")");
        }
#else
        fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd_ < 0) throw Error(ErrorCode::FileAccess, "não foi possível criar " + display(path) + ": " + std::strerror(errno));
#endif
    }
    ~OutFile() { close(); }
    OutFile(const OutFile&) = delete;
    OutFile& operator=(const OutFile&) = delete;

    void write(const std::uint8_t* data, std::size_t n) {
        while (n > 0) {
#ifdef _WIN32
            DWORD done = 0;
            const DWORD part = static_cast<DWORD>(std::min<std::size_t>(n, 1U << 30));
            if (!WriteFile(h_, data, part, &done, nullptr) || done == 0) fail();
#else
            const ssize_t done = ::write(fd_, data, n);
            if (done < 0 && errno == EINTR) continue;
            if (done <= 0) fail();
#endif
            data += done;
            n -= static_cast<std::size_t>(done);
        }
    }
    void write_u32(std::uint32_t v) {
        const std::uint8_t b[4] = {static_cast<std::uint8_t>(v), static_cast<std::uint8_t>(v >> 8),
                                   static_cast<std::uint8_t>(v >> 16), static_cast<std::uint8_t>(v >> 24)};
        write(b, 4);
    }
    // Flushes to stable storage and closes.
    void finish() {
#ifdef _WIN32
        if (!FlushFileBuffers(h_)) fail();
#else
        if (::fsync(fd_) != 0) fail();
#endif
        close();
    }
    void close() noexcept {
#ifdef _WIN32
        if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
#else
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
#endif
    }

private:
    [[noreturn]] void fail() {
        throw Error(ErrorCode::FileAccess, "falha ao gravar " + display(path_) + " (disco cheio ou sem permissão?)");
    }
    fs::path path_;
#ifdef _WIN32
    HANDLE h_ = INVALID_HANDLE_VALUE;
#else
    int fd_ = -1;
#endif
};

// Removes a file on scope exit unless released (temporary files of failed operations).
class FileGuard {
public:
    explicit FileGuard(fs::path p) : path_(std::move(p)) {}
    ~FileGuard() {
        if (!path_.empty()) {
            std::error_code ec;
            fs::remove(path_, ec);
        }
    }
    FileGuard(const FileGuard&) = delete;
    FileGuard& operator=(const FileGuard&) = delete;
    void release() { path_.clear(); }

private:
    fs::path path_;
};

std::array<std::uint8_t, kPrefixSize> make_prefix(const std::array<std::uint8_t, 8>& key_id) {
    std::array<std::uint8_t, kPrefixSize> p{};
    std::memcpy(p.data(), "GKQ1", 4);
    p[4] = kFormatVersion;
    std::copy(key_id.begin(), key_id.end(), p.begin() + 8);
    return p;
}

// ------------------------------------------------------------------ key store

#ifdef _WIN32
constexpr wchar_t kDpapiDescription[] = L"Game Kernel - chave da quarentena";

DATA_BLOB entropy_blob() {
    static const char kEntropy[] = "GameKernel.Quarantine.v1";
    return DATA_BLOB{static_cast<DWORD>(sizeof kEntropy - 1), reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy))};
}

std::vector<std::uint8_t> seal_key(const std::array<std::uint8_t, 32>& key) {
    DATA_BLOB in{static_cast<DWORD>(key.size()), const_cast<BYTE*>(key.data())};
    DATA_BLOB entropy = entropy_blob();
    DATA_BLOB out{};
    if (!CryptProtectData(&in, kDpapiDescription, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        throw Error(ErrorCode::Internal, "DPAPI recusou proteger a chave da quarentena (erro " +
                                             std::to_string(GetLastError()) + ")");
    }
    std::vector<std::uint8_t> blob(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return blob;
}

std::array<std::uint8_t, 32> unseal_key(const std::vector<std::uint8_t>& blob) {
    DATA_BLOB in{static_cast<DWORD>(blob.size()), const_cast<BYTE*>(blob.data())};
    DATA_BLOB entropy = entropy_blob();
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        throw Error(ErrorCode::FileAccess, "a chave da quarentena não pôde ser aberta por este usuário do Windows (DPAPI, erro " +
                                               std::to_string(GetLastError()) + ")");
    }
    std::array<std::uint8_t, 32> key{};
    const bool ok = out.cbData == key.size();
    if (ok) std::memcpy(key.data(), out.pbData, key.size());
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    if (!ok) throw Error(ErrorCode::InvalidFormat, "chave da quarentena com tamanho inválido");
    return key;
}

// SYSTEM, Administrators and the current user only; inheritance from the parent removed.
bool protect_directory(const fs::path& dir) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD len = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &len);
    std::vector<BYTE> buf(len);
    const bool got = len > 0 && GetTokenInformation(token, TokenUser, buf.data(), len, &len);
    CloseHandle(token);
    if (!got) return false;
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &sid)) return false;
    const std::wstring sddl = L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + std::wstring(sid) + L")";
    LocalFree(sid);
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) return false;
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    bool ok = GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present;
    if (ok) {
        ok = SetNamedSecurityInfoW(const_cast<LPWSTR>(dir.c_str()), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                   dacl, nullptr) == ERROR_SUCCESS;
    }
    LocalFree(sd);
    return ok;
}
#endif

std::array<std::uint8_t, 32> load_or_create_key(const fs::path& dir) {
    const fs::path file = dir / "vault.key";
    std::error_code ec;
    if (!fs::exists(file, ec)) {
        std::array<std::uint8_t, 32> key{};
        randombytes_buf(key.data(), key.size());
        const fs::path tmp = dir / ("vault.key." + random_id() + ".tmp");
        FileGuard guard(tmp);
        {
            OutFile out(tmp);
#ifdef _WIN32
            const auto blob = seal_key(key);
            out.write(blob.data(), blob.size());
#else
            out.write(key.data(), key.size());
#endif
            out.finish();
        }
        // Another process may have created the key meanwhile: keep the first one.
        if (!fs::exists(file, ec)) {
            fs::rename(tmp, file, ec);
            if (!ec) {
                guard.release();
                return key;
            }
        }
        sodium_memzero(key.data(), key.size());
    }
    const auto bytes = read_range(file, 0, 4096);
#ifdef _WIN32
    return unseal_key(bytes);
#else
    if (bytes.size() != 32) throw Error(ErrorCode::InvalidFormat, "chave da quarentena corrompida (" + display(file) + ")");
    std::array<std::uint8_t, 32> key{};
    std::copy(bytes.begin(), bytes.end(), key.begin());
    return key;
#endif
}

// ------------------------------------------------------------------ decryption

struct Decrypted {
    Metadata meta;
    std::string sha256;
    std::uint64_t size = 0;
};

std::size_t read_exact(ReadOnlyFile& f, std::uint8_t* buf, std::size_t n) {
    std::size_t got = 0;
    while (got < n) {
        const std::size_t r = f.read(buf + got, n - got);
        if (r == 0) break;
        got += r;
    }
    return got;
}

[[noreturn]] void damaged(const std::string& why) {
    throw Error(ErrorCode::InvalidFormat, "item da quarentena danificado ou adulterado: " + why);
}

// Authenticates the whole item; `sink` receives the plaintext content (may be empty).
template <typename Sink>
Decrypted decrypt(const fs::path& item, const std::array<std::uint8_t, 32>& key,
                  const std::array<std::uint8_t, 8>& key_id, Sink&& sink, CancelToken* cancel) {
    ReadOnlyFile f = ReadOnlyFile::open(item);
    std::array<std::uint8_t, kPrefixSize> prefix{};
    if (read_exact(f, prefix.data(), prefix.size()) != prefix.size() || std::memcmp(prefix.data(), "GKQ1", 4) != 0) {
        damaged("cabeçalho ausente");
    }
    if (prefix[4] != kFormatVersion) damaged("versão de formato desconhecida");
    if (!std::equal(key_id.begin(), key_id.end(), prefix.begin() + 8)) {
        throw Error(ErrorCode::InvalidFormat, "o item foi criado com outra chave da quarentena e não pode ser aberto");
    }
    std::array<std::uint8_t, kHeaderBytes> header{};
    if (read_exact(f, header.data(), header.size()) != header.size()) damaged("cabeçalho truncado");
    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header.data(), key.data()) != 0) damaged("cabeçalho inválido");

    Decrypted out;
    Sha256 sha;
    std::vector<std::uint8_t> cipher, plain;
    for (;;) {
        check_cancel(cancel);
        std::uint8_t lenb[4];
        if (read_exact(f, lenb, 4) != 4) damaged("conteúdo truncado");
        const std::size_t len = static_cast<std::size_t>(lenb[0]) | (static_cast<std::size_t>(lenb[1]) << 8) |
                                (static_cast<std::size_t>(lenb[2]) << 16) | (static_cast<std::size_t>(lenb[3]) << 24);
        if (len < kABytes || len > kChunk + kABytes) damaged("bloco com tamanho inválido");
        cipher.resize(len);
        if (read_exact(f, cipher.data(), len) != len) damaged("conteúdo truncado");
        plain.resize(len - kABytes);
        unsigned long long plain_len = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(&st, plain.data(), &plain_len, &tag, cipher.data(), len,
                                                       prefix.data(), prefix.size()) != 0) {
            damaged("falha de autenticação");
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            if (plain_len > kMaxMetadata) damaged("metadados grandes demais");
            const auto j = json::parse(plain.begin(), plain.begin() + static_cast<std::ptrdiff_t>(plain_len), nullptr, false);
            if (j.is_discarded() || !j.is_object()) damaged("metadados ilegíveis");
            out.meta = metadata_from_json(j);
            std::uint8_t extra = 0;
            if (read_exact(f, &extra, 1) != 0) damaged("dados depois do fim");
            break;
        }
        if (tag != crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) damaged("marcador de bloco inesperado");
        const ByteView chunk(plain.data(), static_cast<std::size_t>(plain_len));
        sha.update(chunk);
        out.size += plain_len;
        sink(chunk);
    }
    sodium_memzero(&st, sizeof st);
    out.sha256 = to_hex(sha.finish());
    if (out.sha256 != out.meta.sha256 || out.size != out.meta.size) damaged("conteúdo não corresponde aos metadados");
    return out;
}

}  // namespace

// ------------------------------------------------------------------ metadata

json to_json(const Metadata& m) {
    return {{"format", "gamekernel-quarantine-item"},
            {"version", 1},
            {"id", m.id},
            {"original_path", m.original_path},
            {"sha256", m.sha256},
            {"size", m.size},
            {"quarantined_at", m.quarantined_at},
            {"reason", m.reason},
            {"classification", m.classification},
            {"detection", m.detection},
            {"risk", static_cast<int>(m.risk)},
            {"scan_id", m.scan_id ? json(*m.scan_id) : json()}};
}

Metadata metadata_from_json(const json& j) {
    Metadata m;
    m.id = j.value("id", "");
    m.original_path = j.value("original_path", "");
    m.sha256 = j.value("sha256", "");
    m.size = j.value("size", std::uint64_t{0});
    m.quarantined_at = j.value("quarantined_at", 0.0);
    m.reason = j.value("reason", "");
    m.classification = j.value("classification", "");
    m.detection = j.value("detection", "");
    m.risk = static_cast<Risk>(std::clamp(j.value("risk", 0), 0, 5));
    if (j.contains("scan_id") && j["scan_id"].is_number_integer()) m.scan_id = j["scan_id"].get<std::int64_t>();
    return m;
}

// ------------------------------------------------------------------ source file of a quarantine

struct Pending::Source {
#ifdef _WIN32
    HANDLE h = INVALID_HANDLE_VALUE;
    ~Source() {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
#else
    int fd = -1;
    struct stat st {};
    ~Source() {
        if (fd >= 0) ::close(fd);
    }
#endif
    fs::path path;

    static std::unique_ptr<Source> open(const fs::path& file) {
        auto s = std::make_unique<Source>();
        s->path = file;
#ifdef _WIN32
        // Others may keep reading; nobody may write, rename or delete while the item is being moved.
        s->h = CreateFileW(file.c_str(), GENERIC_READ | DELETE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (s->h == INVALID_HANDLE_VALUE) {
            const DWORD e = GetLastError();
            if (e == ERROR_SHARING_VIOLATION || e == ERROR_LOCK_VIOLATION) {
                throw Error(ErrorCode::FileAccess, "o arquivo está em uso por outro programa; feche-o e tente de novo");
            }
            if (e == ERROR_ACCESS_DENIED) {
                throw Error(ErrorCode::FileAccess, "acesso negado: o arquivo pode estar em execução ou protegido");
            }
            throw Error(ErrorCode::FileAccess, "não foi possível abrir o arquivo (erro do Windows " + std::to_string(e) + ")");
        }
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(s->h, &info) ||
            (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            throw Error(ErrorCode::FileAccess, "só arquivos comuns podem ir para a quarentena (não pastas ou links)");
        }
#else
        s->fd = ::open(file.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (s->fd < 0) throw Error(ErrorCode::FileAccess, "não foi possível abrir o arquivo: " + std::string(std::strerror(errno)));
        if (::fstat(s->fd, &s->st) != 0 || !S_ISREG(s->st.st_mode)) {
            throw Error(ErrorCode::FileAccess, "só arquivos comuns podem ir para a quarentena (não pastas ou links)");
        }
#endif
        return s;
    }

    std::size_t read(std::uint8_t* buf, std::size_t n) {
#ifdef _WIN32
        DWORD got = 0;
        if (!ReadFile(h, buf, static_cast<DWORD>(n), &got, nullptr)) {
            throw Error(ErrorCode::FileAccess, "falha de leitura (erro do Windows " + std::to_string(GetLastError()) + ")");
        }
        return got;
#else
        for (;;) {
            const ssize_t r = ::read(fd, buf, n);
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) throw Error(ErrorCode::FileAccess, std::string("falha de leitura: ") + std::strerror(errno));
            return static_cast<std::size_t>(r);
        }
#endif
    }

    // Deletes the file that was read (not whatever the path points to now).
    void remove() {
#ifdef _WIN32
        struct {
            DWORD Flags;
        } ex{0x1U | 0x2U | 0x10U};   // DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE (Windows 10 1809+)
        constexpr auto kFileDispositionInfoEx = static_cast<FILE_INFO_BY_HANDLE_CLASS>(21);
        if (!SetFileInformationByHandle(h, kFileDispositionInfoEx, &ex, sizeof ex)) {
            FILE_DISPOSITION_INFO classic{TRUE};
            if (!SetFileInformationByHandle(h, FileDispositionInfo, &classic, sizeof classic)) {
                throw Error(ErrorCode::FileAccess, "o arquivo original não pôde ser removido (erro do Windows " +
                                                       std::to_string(GetLastError()) + "); ele continua no lugar");
            }
        }
        CloseHandle(h);
        h = INVALID_HANDLE_VALUE;
#else
        struct stat now {};
        if (::lstat(path.c_str(), &now) != 0 || now.st_dev != st.st_dev || now.st_ino != st.st_ino) {
            throw Error(ErrorCode::FileAccess, "o arquivo foi substituído durante a operação; nada foi removido");
        }
        if (::unlink(path.c_str()) != 0) {
            throw Error(ErrorCode::FileAccess, std::string("o arquivo original não pôde ser removido: ") + std::strerror(errno));
        }
        ::close(fd);
        fd = -1;
#endif
    }
};

Pending::Pending(Vault& vault, Metadata meta, std::unique_ptr<Source> source)
    : vault_(&vault), meta_(std::move(meta)), source_(std::move(source)) {}

Pending::Pending(Pending&& other) noexcept
    : vault_(other.vault_), meta_(std::move(other.meta_)), source_(std::move(other.source_)), done_(other.done_) {
    other.done_ = true;
}

Pending::~Pending() { abort(); }

void Pending::commit() {
    if (done_) throw Error(ErrorCode::InvalidRequest, "operação de quarentena já concluída");
    source_->remove();
    source_.reset();
    done_ = true;
}

void Pending::abort() noexcept {
    if (done_) return;
    done_ = true;
    source_.reset();
    std::error_code ec;
    fs::remove(vault_->item_path(meta_.id), ec);
}

// ------------------------------------------------------------------ vault

Vault::Vault(fs::path folder) : dir_(std::move(folder)) {}

Vault::~Vault() { sodium_memzero(key_.data(), key_.size()); }

std::unique_ptr<Vault> Vault::open(const fs::path& folder) {
    crypto_init();
    std::error_code ec;
    fs::create_directories(folder, ec);
    if (!fs::is_directory(folder, ec)) throw Error(ErrorCode::FileAccess, "pasta da quarentena indisponível: " + display(folder));
    std::unique_ptr<Vault> v(new Vault(folder));
#ifdef _WIN32
    if (!protect_directory(folder)) {
        v->warnings_.push_back("não foi possível restringir as permissões da pasta da quarentena "
                               "(o sistema de arquivos pode não suportar permissões, como FAT32/exFAT)");
    }
#else
    if (::chmod(folder.c_str(), 0700) != 0) v->warnings_.push_back("não foi possível restringir as permissões da pasta da quarentena");
#endif
    v->key_ = load_or_create_key(folder);
    const std::string kid = sha256_hex(ByteView(v->key_.data(), v->key_.size()));
    for (std::size_t i = 0; i < v->key_id_.size(); ++i) {
        v->key_id_[i] = static_cast<std::uint8_t>(std::stoi(kid.substr(2 * i, 2), nullptr, 16));
    }
    return v;
}

fs::path Vault::item_path(const std::string& id) const {
    if (!valid_id(id)) throw Error(ErrorCode::InvalidRequest, "identificador de item inválido");
    return dir_ / (id + ".gkq");
}

std::string Vault::key_id() const { return to_hex(key_id_); }

Pending Vault::prepare(const Request& request, CancelToken* cancel) {
    std::error_code ec;
    const fs::path absolute = fs::absolute(request.file, ec);
    if (ec) throw Error(ErrorCode::FileAccess, "caminho inválido: " + display(request.file));
    auto source = Pending::Source::open(absolute);

    Metadata meta;
    meta.id = random_id();
    meta.original_path = display(absolute);
    meta.quarantined_at = now_seconds();
    meta.reason = request.reason;
    meta.classification = request.classification;
    meta.detection = request.detection;
    meta.risk = request.risk;
    meta.scan_id = request.scan_id;

    const fs::path part = dir_ / (meta.id + ".gkq.part");
    FileGuard guard(part);
    {
        OutFile out(part);
        const auto prefix = make_prefix(key_id_);
        out.write(prefix.data(), prefix.size());
        crypto_secretstream_xchacha20poly1305_state st;
        std::array<std::uint8_t, kHeaderBytes> header{};
        crypto_secretstream_xchacha20poly1305_init_push(&st, header.data(), key_.data());
        out.write(header.data(), header.size());
        std::vector<std::uint8_t> plain(kChunk), cipher(kChunk + kABytes);
        Sha256 sha;
        auto push = [&](const std::uint8_t* data, std::size_t n, unsigned char tag) {
            unsigned long long clen = 0;
            crypto_secretstream_xchacha20poly1305_push(&st, cipher.data(), &clen, data, n, prefix.data(), prefix.size(), tag);
            out.write_u32(static_cast<std::uint32_t>(clen));
            out.write(cipher.data(), static_cast<std::size_t>(clen));
        };
        for (;;) {
            check_cancel(cancel);
            const std::size_t n = source->read(plain.data(), plain.size());
            if (n == 0) break;
            sha.update(ByteView(plain.data(), n));
            meta.size += n;
            push(plain.data(), n, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        }
        meta.sha256 = to_hex(sha.finish());
        if (request.expected_sha256 && lower_hex(*request.expected_sha256) != meta.sha256) {
            throw Error(ErrorCode::InvalidRequest,
                        "o arquivo mudou desde a análise (SHA-256 diferente); analise-o de novo antes de colocá-lo em quarentena");
        }
        const std::string doc = to_json(meta).dump();
        push(reinterpret_cast<const std::uint8_t*>(doc.data()), doc.size(), crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        sodium_memzero(&st, sizeof st);
        sodium_memzero(plain.data(), plain.size());
        out.finish();
    }
    // Prove the stored copy can be restored before the original is touched.
    const auto check = decrypt(part, key_, key_id_, [](ByteView) {}, cancel);
    if (check.sha256 != meta.sha256) damaged("verificação após gravar");
    const fs::path final_path = item_path(meta.id);
    fs::rename(part, final_path, ec);
    if (ec) throw Error(ErrorCode::FileAccess, "não foi possível concluir a gravação na quarentena: " + ec.message());
    guard.release();
    return Pending(*this, std::move(meta), std::move(source));
}

Metadata Vault::inspect(const std::string& id, CancelToken* cancel) {
    return decrypt(item_path(id), key_, key_id_, [](ByteView) {}, cancel).meta;
}

Metadata Vault::restore(const std::string& id, const fs::path& destination, bool overwrite,
                        const std::optional<std::string>& expected_sha256, CancelToken* cancel) {
    const fs::path item = item_path(id);
    std::error_code ec;
    if (!fs::exists(item, ec)) throw Error(ErrorCode::FileAccess, "o arquivo do item não existe mais na quarentena");
    const fs::path target = fs::absolute(destination, ec);
    if (ec || target.filename().empty()) throw Error(ErrorCode::InvalidRequest, "destino inválido");
    if (fs::exists(fs::symlink_status(target, ec)) && !overwrite) {
        throw Error(ErrorCode::FileAccess, "já existe um arquivo em " + display(target) + "; escolha outro destino");
    }
    if (fs::is_directory(target, ec)) throw Error(ErrorCode::FileAccess, "o destino é uma pasta: " + display(target));
    fs::create_directories(target.parent_path(), ec);
    const fs::path tmp = target.parent_path() / ("." + id + ".gkrestore");
    fs::remove(tmp, ec);
    FileGuard guard(tmp);
    Decrypted result;
    {
        OutFile out(tmp);
        result = decrypt(item, key_, key_id_, [&](ByteView chunk) { out.write(chunk.data(), chunk.size()); }, cancel);
        out.finish();
    }
    if (expected_sha256 && *expected_sha256 != result.sha256) {
        throw Error(ErrorCode::InvalidFormat, "o conteúdo restaurado não corresponde ao registro do banco de dados");
    }
    fs::rename(tmp, target, ec);
    if (ec) throw Error(ErrorCode::FileAccess, "não foi possível gravar " + display(target) + ": " + ec.message());
    guard.release();
    return result.meta;
}

void Vault::erase(const std::string& id) {
    std::error_code ec;
    fs::remove(item_path(id), ec);
    if (ec) throw Error(ErrorCode::FileAccess, "não foi possível apagar o item da quarentena: " + ec.message());
}

VerifyReport Vault::verify(const std::vector<std::string>& known, CancelToken* cancel) {
    VerifyReport report;
    std::set<std::string> expected(known.begin(), known.end()), seen;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir_, ec)) {
        const fs::path p = entry.path();
        if (p.extension() != ".gkq") continue;
        const std::string id = text::path_utf8(p.stem());
        if (!valid_id(id)) continue;
        seen.insert(id);
        try {
            Metadata m = inspect(id, cancel);
            if (m.id != id) damaged("identificador interno diferente do nome do arquivo");
            if (expected.count(id)) {
                report.ok.push_back(id);
            } else {
                report.unknown.push_back(std::move(m));
            }
        } catch (const Error& e) {
            if (e.code() == ErrorCode::Cancelled) throw;
            report.damaged.emplace_back(id, e.what());
        }
    }
    for (const auto& id : expected) {
        if (!seen.count(id)) report.damaged.emplace_back(id, "o arquivo do item não existe na pasta da quarentena");
    }
    return report;
}

// ------------------------------------------------------------------ manager (vault + database + audit)

namespace {
db::QuarantineRecord record_of(const Metadata& m, const std::string& status, const std::string& key_id) {
    db::QuarantineRecord r;
    r.id = m.id;
    r.original_path = m.original_path;
    r.sha256 = m.sha256;
    r.size = m.size;
    r.quarantined_at = m.quarantined_at;
    r.reason = m.reason;
    r.classification = m.classification;
    r.detection = m.detection;
    r.risk = static_cast<int>(m.risk);
    r.scan_id = m.scan_id;
    r.stored_name = m.id + ".gkq";
    r.status = status;
    r.meta = {{"format", "gkq1"}, {"key_id", key_id}};
    return r;
}
}  // namespace

Metadata Manager::quarantine(const Request& request, CancelToken* cancel) {
    Pending pending = vault_.prepare(request, cancel);   // aborts (removes the copy) if anything below throws
    const Metadata meta = pending.metadata();
    db_.add_quarantine_item(record_of(meta, "quarantined", vault_.key_id()));
    try {
        pending.commit();
    } catch (...) {
        db_.remove_quarantine_item(meta.id);
        throw;
    }
    db_.add_quarantine_event(meta.id, "quarantine", meta.original_path);
    db_.append_audit("quarantine", meta.original_path + " (SHA-256 " + meta.sha256 + ")", "user");
    return meta;
}

std::filesystem::path Manager::restore(const std::string& id, const std::optional<fs::path>& destination, bool overwrite,
                                       CancelToken* cancel) {
    const auto rec = db_.quarantine_item(id);
    if (!rec) throw Error(ErrorCode::InvalidRequest, "item da quarentena não encontrado");
    if (rec->status != "quarantined") throw Error(ErrorCode::InvalidRequest, "o item não está mais na quarentena (" + rec->status + ")");
    const fs::path target = destination ? *destination : text::utf8_path(rec->original_path);
    vault_.restore(id, target, overwrite, rec->sha256, cancel);
    const std::string where = display(fs::absolute(target));
    db_.update_quarantine_status(id, "restored");
    db_.add_quarantine_event(id, "restore", where);
    db_.append_audit("restore", where + " (SHA-256 " + rec->sha256 + ")", "user");
    std::error_code ec;
    fs::remove(vault_.item_path(id), ec);   // the record already says restored; a leftover copy is cleaned by verify()
    return fs::absolute(target);
}

void Manager::erase(const std::string& id) {
    const auto rec = db_.quarantine_item(id);
    if (!rec) throw Error(ErrorCode::InvalidRequest, "item da quarentena não encontrado");
    if (rec->status != "quarantined") throw Error(ErrorCode::InvalidRequest, "o item não está mais na quarentena (" + rec->status + ")");
    vault_.erase(id);
    db_.update_quarantine_status(id, "deleted");
    db_.add_quarantine_event(id, "delete", rec->original_path);
    db_.append_audit("delete", rec->original_path + " (SHA-256 " + rec->sha256 + ")", "user");
}

VerifyReport Manager::verify(CancelToken* cancel) {
    std::vector<std::string> ids;
    for (const auto& r : db_.list_quarantine("quarantined")) ids.push_back(r.id);
    VerifyReport report = vault_.verify(ids, cancel);
    for (const auto& m : report.unknown) {
        if (const auto existing = db_.quarantine_item(m.id)) {
            // Copy left behind by a restore/delete that was interrupted after the database was updated.
            if (existing->status != "quarantined") vault_.erase(m.id);
            continue;
        }
        db_.add_quarantine_item(record_of(m, "quarantined", vault_.key_id()));
        db_.add_quarantine_event(m.id, "recovered", m.original_path);
        db_.append_audit("quarantine_recovered", m.original_path + " (SHA-256 " + m.sha256 + ")", "core");
    }
    return report;
}

}  // namespace gk::quarantine
