#include "gk/file_view.hpp"

#include <string>
#include <utility>

#include "gk/error.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace gk {

namespace {

std::string describe(const std::filesystem::path& path) {
    return path.u8string().empty() ? std::string("<vazio>") : std::string(reinterpret_cast<const char*>(path.u8string().c_str()));
}

#ifdef _WIN32
std::string last_error_text() {
    const DWORD code = GetLastError();
    return "erro do Windows " + std::to_string(code);
}
#else
std::string last_error_text() { return std::strerror(errno); }
#endif

}  // namespace

// ------------------------------------------------------------------ ReadOnlyFile

ReadOnlyFile ReadOnlyFile::open(const std::filesystem::path& path) {
    ReadOnlyFile file;
#ifdef _WIN32
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        throw Error(ErrorCode::FileAccess, "não foi possível abrir " + describe(path) + ": " + last_error_text());
    }
    file.handle_ = reinterpret_cast<std::intptr_t>(h);
    if (GetFileType(h) != FILE_TYPE_DISK) {
        throw Error(ErrorCode::FileAccess, describe(path) + " não é um arquivo comum");
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size)) {
        throw Error(ErrorCode::FileAccess, "tamanho indisponível: " + describe(path));
    }
    file.size_ = static_cast<std::uint64_t>(size.QuadPart);
#else
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) {
        throw Error(ErrorCode::FileAccess, "não foi possível abrir " + describe(path) + ": " + last_error_text());
    }
    file.handle_ = fd;
    struct stat st {};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        throw Error(ErrorCode::FileAccess, describe(path) + " não é um arquivo comum");
    }
    // Back to blocking mode for regular-file reads.
    const int flags = fcntl(fd, F_GETFL);
    if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    file.size_ = static_cast<std::uint64_t>(st.st_size);
#endif
    return file;
}

ReadOnlyFile::ReadOnlyFile(ReadOnlyFile&& other) noexcept
    : handle_(std::exchange(other.handle_, -1)), size_(other.size_) {}

ReadOnlyFile& ReadOnlyFile::operator=(ReadOnlyFile&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = std::exchange(other.handle_, -1);
        size_ = other.size_;
    }
    return *this;
}

ReadOnlyFile::~ReadOnlyFile() { close(); }

void ReadOnlyFile::close() noexcept {
    if (handle_ == -1) return;
#ifdef _WIN32
    CloseHandle(reinterpret_cast<HANDLE>(handle_));
#else
    ::close(static_cast<int>(handle_));
#endif
    handle_ = -1;
}

std::size_t ReadOnlyFile::read(std::uint8_t* buffer, std::size_t count) {
#ifdef _WIN32
    const DWORD chunk = count > 0x40000000u ? 0x40000000u : static_cast<DWORD>(count);
    DWORD got = 0;
    if (!ReadFile(reinterpret_cast<HANDLE>(handle_), buffer, chunk, &got, nullptr)) {
        throw Error(ErrorCode::FileAccess, "falha de leitura: " + last_error_text());
    }
    return got;
#else
    for (;;) {
        const ssize_t got = ::read(static_cast<int>(handle_), buffer, count);
        if (got >= 0) return static_cast<std::size_t>(got);
        if (errno != EINTR) throw Error(ErrorCode::FileAccess, "falha de leitura: " + last_error_text());
    }
#endif
}

std::size_t ReadOnlyFile::read_at(std::uint64_t offset, std::uint8_t* buffer, std::size_t count) {
#ifdef _WIN32
    OVERLAPPED ov{};
    ov.Offset = static_cast<DWORD>(offset & 0xFFFFFFFFu);
    ov.OffsetHigh = static_cast<DWORD>(offset >> 32);
    const DWORD chunk = count > 0x40000000u ? 0x40000000u : static_cast<DWORD>(count);
    DWORD got = 0;
    if (!ReadFile(reinterpret_cast<HANDLE>(handle_), buffer, chunk, &got, &ov)) {
        if (GetLastError() == ERROR_HANDLE_EOF) return 0;
        throw Error(ErrorCode::FileAccess, "falha de leitura: " + last_error_text());
    }
    return got;
#else
    for (;;) {
        const ssize_t got = ::pread(static_cast<int>(handle_), buffer, count, static_cast<off_t>(offset));
        if (got >= 0) return static_cast<std::size_t>(got);
        if (errno != EINTR) throw Error(ErrorCode::FileAccess, "falha de leitura: " + last_error_text());
    }
#endif
}

// ------------------------------------------------------------------ MappedFile

MappedFile MappedFile::open(const std::filesystem::path& path) {
    ReadOnlyFile file = ReadOnlyFile::open(path);
    MappedFile mapped;
    if (file.size() == 0) return mapped;
    if (file.size() > static_cast<std::uint64_t>(static_cast<std::size_t>(-1))) {
        throw Error(ErrorCode::ResourceLimit, "arquivo grande demais para mapear: " + describe(path));
    }
#ifdef _WIN32
    HANDLE section = CreateFileMappingW(reinterpret_cast<HANDLE>(file.native_handle()), nullptr, PAGE_READONLY, 0, 0,
                                        nullptr);
    if (section == nullptr) {
        throw Error(ErrorCode::FileAccess, "falha ao mapear " + describe(path) + ": " + last_error_text());
    }
    void* view = MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
    if (view == nullptr) {
        CloseHandle(section);
        throw Error(ErrorCode::FileAccess, "falha ao mapear " + describe(path) + ": " + last_error_text());
    }
    mapped.mapping_ = reinterpret_cast<std::intptr_t>(section);
    mapped.data_ = static_cast<const std::uint8_t*>(view);
#else
    void* view = mmap(nullptr, static_cast<std::size_t>(file.size()), PROT_READ, MAP_PRIVATE,
                      static_cast<int>(file.native_handle()), 0);
    if (view == MAP_FAILED) {
        throw Error(ErrorCode::FileAccess, "falha ao mapear " + describe(path) + ": " + last_error_text());
    }
    mapped.data_ = static_cast<const std::uint8_t*>(view);
#endif
    mapped.size_ = static_cast<std::size_t>(file.size());
    return mapped;
}

MappedFile::MappedFile(MappedFile&& other) noexcept
    : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)),
      mapping_(std::exchange(other.mapping_, 0)) {}

MappedFile& MappedFile::operator=(MappedFile&& other) noexcept {
    if (this != &other) {
        close();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
        mapping_ = std::exchange(other.mapping_, 0);
    }
    return *this;
}

MappedFile::~MappedFile() { close(); }

void MappedFile::close() noexcept {
#ifdef _WIN32
    if (data_ != nullptr) UnmapViewOfFile(data_);
    if (mapping_ != 0) CloseHandle(reinterpret_cast<HANDLE>(mapping_));
#else
    if (data_ != nullptr) munmap(const_cast<std::uint8_t*>(data_), size_);
#endif
    data_ = nullptr;
    size_ = 0;
    mapping_ = 0;
}

std::vector<std::uint8_t> read_range(const std::filesystem::path& path, std::uint64_t offset, std::size_t count) {
    ReadOnlyFile file = ReadOnlyFile::open(path);
    std::vector<std::uint8_t> out;
    if (offset >= file.size()) return out;
    const std::uint64_t avail = file.size() - offset;
    out.resize(static_cast<std::size_t>(avail < count ? avail : count));
    std::size_t done = 0;
    while (done < out.size()) {
        const std::size_t got = file.read_at(offset + done, out.data() + done, out.size() - done);
        if (got == 0) break;
        done += got;
    }
    out.resize(done);
    return out;
}

}  // namespace gk
