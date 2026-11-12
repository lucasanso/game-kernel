// Bounded, non-owning view over untrusted bytes.
//
// Every access is bounds-checked and every offset computation is overflow-checked.
// Parsers must read file data exclusively through this type: no raw pointer arithmetic
// on file contents anywhere else in the code base.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

namespace gk {

// a + b without wrap-around. Returns false on overflow.
constexpr bool checked_add(std::size_t a, std::size_t b, std::size_t& out) noexcept {
    if (a > static_cast<std::size_t>(-1) - b) return false;
    out = a + b;
    return true;
}

class ByteView {
public:
    constexpr ByteView() noexcept = default;
    constexpr ByteView(const std::uint8_t* data, std::size_t size) noexcept
        : data_(size ? data : nullptr), size_(data ? size : 0) {}
    explicit ByteView(std::span<const std::uint8_t> s) noexcept : ByteView(s.data(), s.size()) {}
    explicit ByteView(std::string_view s) noexcept
        : ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()) {}

    [[nodiscard]] constexpr std::size_t size() const noexcept { return size_; }
    [[nodiscard]] constexpr bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] constexpr const std::uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] std::span<const std::uint8_t> span() const noexcept { return {data_, size_}; }

    // True when [offset, offset+len) lies inside the view.
    [[nodiscard]] constexpr bool has(std::size_t offset, std::size_t len) const noexcept {
        std::size_t end = 0;
        return checked_add(offset, len, end) && end <= size_;
    }

    [[nodiscard]] std::optional<ByteView> sub(std::size_t offset, std::size_t len) const noexcept {
        if (!has(offset, len)) return std::nullopt;
        return ByteView(data_ + offset, len);
    }

    // Sub-view clamped to the available bytes (possibly empty).
    [[nodiscard]] ByteView clamp(std::size_t offset, std::size_t len) const noexcept {
        if (offset >= size_) return {};
        const std::size_t avail = size_ - offset;
        return ByteView(data_ + offset, len < avail ? len : avail);
    }

    [[nodiscard]] ByteView prefix(std::size_t len) const noexcept { return clamp(0, len); }

    [[nodiscard]] std::optional<std::uint8_t> u8(std::size_t offset) const noexcept {
        if (offset >= size_) return std::nullopt;
        return data_[offset];
    }

    // Little-endian integer read (PE and most container formats are little-endian).
    template <typename T>
    [[nodiscard]] std::optional<T> le(std::size_t offset) const noexcept {
        static_assert(std::is_integral_v<T> && std::is_unsigned_v<T>);
        if (!has(offset, sizeof(T))) return std::nullopt;
        T value = 0;
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            value |= static_cast<T>(static_cast<T>(data_[offset + i]) << (8 * i));
        }
        return value;
    }

    [[nodiscard]] bool equals_at(std::size_t offset, std::string_view literal) const noexcept {
        if (!has(offset, literal.size())) return false;
        return literal.empty() || std::memcmp(data_ + offset, literal.data(), literal.size()) == 0;
    }

    [[nodiscard]] bool starts_with(std::string_view literal) const noexcept { return equals_at(0, literal); }

    // Find a literal inside [0, limit). Returns npos when absent.
    [[nodiscard]] std::size_t find(std::string_view literal, std::size_t start = 0,
                                   std::size_t limit = static_cast<std::size_t>(-1)) const noexcept {
        const std::size_t end = limit < size_ ? limit : size_;
        if (literal.empty() || start >= end || literal.size() > end - start) return npos;
        for (std::size_t i = start; i + literal.size() <= end; ++i) {
            if (data_[i] == static_cast<std::uint8_t>(literal[0]) &&
                std::memcmp(data_ + i, literal.data(), literal.size()) == 0) {
                return i;
            }
        }
        return npos;
    }

    [[nodiscard]] std::string to_string() const { return {reinterpret_cast<const char*>(data_), size_}; }

    static constexpr std::size_t npos = static_cast<std::size_t>(-1);

private:
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

}  // namespace gk
