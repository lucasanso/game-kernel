// Archive inspection on libarchive — in memory only, nothing is ever written to disk.
//
// Safety properties:
// * explicit format/filter whitelist (no mtree — it can reference files on disk — and no filter
//   that falls back to running an external program);
// * limits on members, per-member size, total decompressed bytes (shared across nesting levels),
//   compression ratio and nesting depth; exceeding a limit stops that branch and is reported;
// * member names are only *reported* (sanitised); they never become filesystem paths;
// * encrypted members, symlinks, absolute paths and ".." segments are flagged.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "gk/byte_view.hpp"
#include "gk/cancel.hpp"

namespace gk::archive {

struct Limits {
    std::uint64_t max_total_bytes = 2048ull << 20;    // decompressed bytes per top-level archive (all depths)
    std::uint64_t max_member_bytes = 256ull << 20;    // larger members are read up to this prefix only
    std::uint64_t max_members = 20000;                // per top-level archive (all depths)
    double max_ratio = 250.0;                         // decompressed / compressed
    std::uint64_t ratio_min_bytes = 32ull << 20;      // ratio enforced once this much was decompressed
    unsigned max_depth = 4;                           // nested archives below the top level
};

struct Member {
    std::string path;              // chain inside the top-level archive: "inner.zip::dir/file.exe"
    std::string name;              // member path within its own archive (sanitised UTF-8)
    unsigned depth = 0;            // 0 = member of the top-level archive
    std::uint64_t declared_size = 0;
    bool size_known = false;
    std::uint64_t bytes_read = 0;
    bool is_directory = false;
    bool is_symlink = false;
    std::string link_target;
    bool encrypted = false;
    bool complete = false;         // all data was read
    std::vector<std::string> anomalies;   // absolute_path | path_traversal | symlink | hardlink | encrypted |
                                          // member_too_large | read_error | special_file
};

struct Report {
    std::string format;                // format of the top-level archive as named by libarchive
    std::vector<std::string> nested_formats;
    std::uint64_t members_seen = 0;
    std::uint64_t total_bytes = 0;     // decompressed bytes read (all depths)
    bool complete = true;              // false when a limit, an error or cancellation stopped reading
    bool encrypted_entries = false;
    std::vector<std::string> anomalies;   // decompression_bomb | too_many_members | total_limit | depth_limit |
                                          // corrupt | cancelled
    std::vector<std::string> errors;
};

enum class Want { Skip, Read };

struct Visitor {
    // Decide whether the member's data is needed (headers are always reported).
    std::function<Want(const Member&)> on_entry;
    // Data of a member (prefix when `!member.complete`). Called before nested archives are expanded.
    std::function<void(const Member&, ByteView data)> on_data;
    // Return true when `data` is an archive that should be expanded (nested analysis).
    std::function<bool(const Member&, ByteView data)> is_archive;
};

// Walk an archive held in memory, expanding nested archives up to `limits.max_depth`.
Report walk(ByteView archive, const Limits& limits, const Visitor& visitor, CancelToken* cancel = nullptr);

// Quick probe: does libarchive recognise these bytes as an archive it may open? (No data is decompressed.)
bool recognised(ByteView data);

std::string libarchive_version();

}  // namespace gk::archive
