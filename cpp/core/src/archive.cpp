#include "gk/archive.hpp"

#include <archive.h>
#include <archive_entry.h>

#include <algorithm>
#include <memory>
#include <mutex>

#include "gk/text.hpp"

namespace gk::archive {

namespace {

constexpr std::size_t kChunk = 64 * 1024;
constexpr std::size_t kMaxNameLength = 1024;

struct NativeFilters {
    bool gzip = false, bzip2 = false, xz = false, lzma = false, zstd = false, lz4 = false;
};

// libarchive returns ARCHIVE_WARN when a filter is only available through an external program.
// Such filters are never enabled: the scanner must not spawn helper processes on hostile input.
const NativeFilters& native_filters() {
    static NativeFilters filters;
    static std::once_flag once;
    std::call_once(once, [] {
        auto probe = [](int (*fn)(struct archive*)) {
            struct archive* a = archive_read_new();
            const bool ok = fn(a) == ARCHIVE_OK;
            archive_read_free(a);
            return ok;
        };
        filters.gzip = probe(archive_read_support_filter_gzip);
        filters.bzip2 = probe(archive_read_support_filter_bzip2);
        filters.xz = probe(archive_read_support_filter_xz);
        filters.lzma = probe(archive_read_support_filter_lzma);
        filters.zstd = probe(archive_read_support_filter_zstd);
        filters.lz4 = probe(archive_read_support_filter_lz4);
    });
    return filters;
}

class Reader {
public:
    explicit Reader(bool raw) : a_(archive_read_new()) {
        const NativeFilters& f = native_filters();
        if (f.gzip) archive_read_support_filter_gzip(a_);
        if (f.bzip2) archive_read_support_filter_bzip2(a_);
        if (f.xz) archive_read_support_filter_xz(a_);
        if (f.lzma) archive_read_support_filter_lzma(a_);
        if (f.zstd) archive_read_support_filter_zstd(a_);
        if (f.lz4) archive_read_support_filter_lz4(a_);
        if (raw) {
            archive_read_support_format_raw(a_);
        } else {
            archive_read_support_format_zip(a_);
            archive_read_support_format_7zip(a_);
            archive_read_support_format_rar(a_);
            archive_read_support_format_rar5(a_);
            archive_read_support_format_iso9660(a_);
            archive_read_support_format_cab(a_);
            archive_read_support_format_tar(a_);
            archive_read_support_format_cpio(a_);
            archive_read_support_format_lha(a_);
        }
    }
    ~Reader() { archive_read_free(a_); }
    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;
    struct archive* get() const { return a_; }

private:
    struct archive* a_;
};

bool compressed_stream(ByteView d) {
    return d.starts_with("\x1f\x8b") || d.starts_with("BZh") || d.starts_with(std::string_view("\xfd" "7zXZ\x00", 6)) ||
           d.starts_with("\x28\xb5\x2f\xfd") || d.starts_with("\x04\x22\x4d\x18");
}

std::string sanitize(const char* utf8, const char* raw) {
    std::string name;
    if (utf8 != nullptr) {
        name = utf8;
    } else if (raw != nullptr) {
        name = text::escape_bytes(raw);
    }
    std::string out;
    out.reserve(std::min(name.size(), kMaxNameLength));
    for (char ch : name) {
        if (out.size() >= kMaxNameLength) {
            out += "\xE2\x80\xA6";
            break;
        }
        const auto b = static_cast<unsigned char>(ch);
        out.push_back(b < 0x20 || b == 0x7F ? '?' : ch);
    }
    return out;
}

void name_anomalies(Member& m) {
    std::string n = m.name;
    std::replace(n.begin(), n.end(), '\\', '/');
    if (!n.empty() && (n[0] == '/' || (n.size() > 1 && n[1] == ':'))) m.anomalies.emplace_back("absolute_path");
    std::size_t start = 0;
    while (start <= n.size()) {
        const std::size_t end = n.find('/', start);
        const std::string segment = n.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (segment == "..") {
            m.anomalies.emplace_back("path_traversal");
            break;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
}

void add_unique(std::vector<std::string>& list, const std::string& value) {
    if (std::find(list.begin(), list.end(), value) == list.end()) list.push_back(value);
}

struct Context {
    const Limits& limits;
    const Visitor& visitor;
    CancelToken* cancel;
    Report& report;
};

// Returns false when the whole walk must stop (global limit, bomb or cancellation).
bool walk_level(ByteView data, const std::string& prefix, unsigned depth, Context& ctx) {
    Report& rep = ctx.report;
    bool raw = false;
    auto reader = std::make_unique<Reader>(false);
    if (archive_read_open_memory(reader->get(), data.data(), data.size()) != ARCHIVE_OK) {
        if (!compressed_stream(data)) {
            rep.errors.push_back((prefix.empty() ? std::string("arquivo") : prefix) + ": formato não reconhecido");
            add_unique(rep.anomalies, "corrupt");
            rep.complete = false;
            return true;
        }
        reader = std::make_unique<Reader>(true);
        raw = true;
        if (archive_read_open_memory(reader->get(), data.data(), data.size()) != ARCHIVE_OK) {
            rep.errors.push_back(prefix + ": " + (archive_error_string(reader->get()) ? archive_error_string(reader->get()) : "erro"));
            add_unique(rep.anomalies, "corrupt");
            rep.complete = false;
            return true;
        }
    }
    struct archive* a = reader->get();
    std::uint64_t level_bytes = 0;
    bool first = true;
    for (;;) {
        if (ctx.cancel != nullptr && !ctx.cancel->wait_if_paused()) {
            add_unique(rep.anomalies, "cancelled");
            rep.complete = false;
            return false;
        }
        struct archive_entry* entry = nullptr;
        const int rc = archive_read_next_header(a, &entry);
        if (rc == ARCHIVE_EOF) break;
        if (rc < ARCHIVE_WARN) {
            const char* err = archive_error_string(a);
            rep.errors.push_back((prefix.empty() ? std::string("arquivo") : prefix) + ": " + (err ? err : "erro de leitura"));
            add_unique(rep.anomalies, "corrupt");
            rep.complete = false;
            break;
        }
        if (first) {
            const char* fmt = archive_format_name(a);
            const std::string format = raw ? std::string("raw (") + (archive_filter_name(a, 0) ? archive_filter_name(a, 0) : "?") + ")"
                                           : (fmt ? fmt : "?");
            if (depth == 0) {
                rep.format = format;
            } else {
                rep.nested_formats.push_back(format);
            }
            first = false;
        }
        if (++rep.members_seen > ctx.limits.max_members) {
            add_unique(rep.anomalies, "too_many_members");
            rep.complete = false;
            return false;
        }
        Member m;
        m.depth = depth;
        m.name = sanitize(archive_entry_pathname_utf8(entry), archive_entry_pathname(entry));
        if (raw && (m.name.empty() || m.name == "data")) m.name = "(conteúdo descompactado)";
        m.path = prefix.empty() ? m.name : prefix + "::" + m.name;
        name_anomalies(m);
        const auto type = archive_entry_filetype(entry);
        m.is_directory = type == AE_IFDIR;
        m.is_symlink = type == AE_IFLNK;
        if (m.is_symlink) {
            m.link_target = sanitize(archive_entry_symlink_utf8(entry), archive_entry_symlink(entry));
            m.anomalies.emplace_back("symlink");
        }
        if (archive_entry_hardlink(entry) != nullptr) m.anomalies.emplace_back("hardlink");
        const bool regular = type == AE_IFREG || (raw && type == 0);
        if (!m.is_directory && !m.is_symlink && !regular) m.anomalies.emplace_back("special_file");
        m.size_known = archive_entry_size_is_set(entry) != 0;
        if (m.size_known && archive_entry_size(entry) >= 0) m.declared_size = static_cast<std::uint64_t>(archive_entry_size(entry));
        if (archive_entry_is_encrypted(entry)) {
            m.encrypted = true;
            m.anomalies.emplace_back("encrypted");
            rep.encrypted_entries = true;
        }

        Want want = ctx.visitor.on_entry ? ctx.visitor.on_entry(m) : Want::Read;
        if (!regular || m.encrypted || m.is_directory || m.is_symlink) want = Want::Skip;
        if (want == Want::Skip) continue;

        std::vector<std::uint8_t> buffer;
        const std::uint64_t cap = ctx.limits.max_member_bytes;
        if (m.size_known) buffer.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(m.declared_size, cap)));
        std::uint8_t chunk[kChunk];
        bool stop_all = false;
        bool truncated = false;
        for (;;) {
            if (ctx.cancel != nullptr && !ctx.cancel->wait_if_paused()) {
                add_unique(rep.anomalies, "cancelled");
                rep.complete = false;
                stop_all = true;
                break;
            }
            const la_ssize_t n = archive_read_data(a, chunk, sizeof chunk);
            if (n < 0) {
                // libarchive reports an error for some zero-length members (e.g. LZMA in ZIP); when the header
                // declares no data there is nothing that could have been missed.
                if (m.size_known && m.declared_size == 0 && buffer.empty()) {
                    m.complete = true;
                    break;
                }
                const char* err = archive_error_string(a);
                m.anomalies.emplace_back("read_error");
                rep.errors.push_back(m.path + ": " + (err ? err : "erro ao descompactar"));
                rep.complete = false;
                break;
            }
            if (n == 0) {
                m.complete = true;
                break;
            }
            const auto got = static_cast<std::uint64_t>(n);
            rep.total_bytes += got;
            level_bytes += got;
            const std::uint64_t room = cap > buffer.size() ? cap - buffer.size() : 0;
            buffer.insert(buffer.end(), chunk, chunk + static_cast<std::size_t>(std::min<std::uint64_t>(got, room)));
            if (rep.total_bytes > ctx.limits.max_total_bytes) {
                add_unique(rep.anomalies, "total_limit");
                rep.complete = false;
                stop_all = true;
                break;
            }
            const auto consumed = static_cast<std::uint64_t>(std::max<la_int64_t>(archive_filter_bytes(a, -1), 1));
            if (level_bytes > ctx.limits.ratio_min_bytes &&
                static_cast<double>(level_bytes) / static_cast<double>(consumed) > ctx.limits.max_ratio) {
                add_unique(rep.anomalies, "decompression_bomb");
                rep.complete = false;
                stop_all = true;
                break;
            }
            // Oversized members keep being read (and discarded) instead of skipped: skipping a member of a
            // solid archive decompresses it internally, outside the budget and cancellation checks.
            if (got > room && !truncated) {
                truncated = true;
                m.anomalies.emplace_back("member_too_large");
                rep.complete = false;
            }
        }
        if (truncated) m.complete = false;
        m.bytes_read = buffer.size();
        const ByteView view(buffer.data(), buffer.size());
        if (ctx.visitor.on_data) ctx.visitor.on_data(m, view);
        if (stop_all) return false;
        if (ctx.visitor.is_archive && ctx.visitor.is_archive(m, view)) {
            if (depth + 1 > ctx.limits.max_depth) {
                add_unique(rep.anomalies, "depth_limit");
                rep.complete = false;
            } else if (!walk_level(view, m.path, depth + 1, ctx)) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace

Report walk(ByteView data, const Limits& limits, const Visitor& visitor, CancelToken* cancel) {
    Report report;
    Context ctx{limits, visitor, cancel, report};
    walk_level(data, std::string(), 0, ctx);
    return report;
}

bool recognised(ByteView data) {
    Reader reader(false);
    if (archive_read_open_memory(reader.get(), data.data(), data.size()) != ARCHIVE_OK) return false;
    struct archive_entry* entry = nullptr;
    return archive_read_next_header(reader.get(), &entry) >= ARCHIVE_WARN;
}

std::string libarchive_version() { return archive_version_details(); }

}  // namespace gk::archive
