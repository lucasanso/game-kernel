// Read-only file access for analysis.
//
// Files are opened with full sharing (read/write/delete) so the scanner never blocks a game,
// an installer or another antivirus. Only regular files are accepted (no devices, pipes or
// sockets), which prevents hangs on special files.
#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

#include "gk/byte_view.hpp"

namespace gk {

class ReadOnlyFile {
public:
    // Throws gk::Error(FileAccess) on failure.
    static ReadOnlyFile open(const std::filesystem::path& path);

    ReadOnlyFile(ReadOnlyFile&& other) noexcept;
    ReadOnlyFile& operator=(ReadOnlyFile&& other) noexcept;
    ReadOnlyFile(const ReadOnlyFile&) = delete;
    ReadOnlyFile& operator=(const ReadOnlyFile&) = delete;
    ~ReadOnlyFile();

    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }
    // Sequential read; returns bytes read (0 at end of file). Throws on I/O error.
    std::size_t read(std::uint8_t* buffer, std::size_t count);
    // Positional read; returns bytes read (may be short at end of file).
    std::size_t read_at(std::uint64_t offset, std::uint8_t* buffer, std::size_t count);
    [[nodiscard]] std::intptr_t native_handle() const noexcept { return handle_; }

private:
    ReadOnlyFile() = default;
    void close() noexcept;
    std::intptr_t handle_ = -1;
    std::uint64_t size_ = 0;
};

// Read-only memory mapping. Empty files produce an empty view without a mapping.
class MappedFile {
public:
    static MappedFile open(const std::filesystem::path& path);

    MappedFile(MappedFile&& other) noexcept;
    MappedFile& operator=(MappedFile&& other) noexcept;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    ~MappedFile();

    [[nodiscard]] ByteView view() const noexcept { return ByteView(data_, size_); }
    [[nodiscard]] std::uint64_t size() const noexcept { return size_; }

private:
    MappedFile() = default;
    void close() noexcept;
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::intptr_t mapping_ = 0;  // Windows section handle
};

// Read at most `count` bytes starting at `offset` (short or empty result near end of file).
std::vector<std::uint8_t> read_range(const std::filesystem::path& path, std::uint64_t offset, std::size_t count);

}  // namespace gk
