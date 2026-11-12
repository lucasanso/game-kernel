// YARA engine on libyara: compilation with per-file isolation, `include` disabled, external
// variables, thread-safe scanning (one scanner per call), cancellation and match limits.
#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "gk/byte_view.hpp"
#include "gk/cancel.hpp"

namespace gk::yara {

struct StringMatch {
    std::string identifier;     // "$s0"
    std::uint64_t offset = 0;   // offset inside the scanned buffer
    std::uint32_t length = 0;   // matched length
    std::string excerpt;        // printable rendering of the matched bytes (UTF-16 decoded when wide)
};

struct RuleMatch {
    std::string rule;
    std::string ns;
    std::vector<std::string> tags;
    std::map<std::string, std::string> meta;   // integers/booleans rendered as text
    std::vector<StringMatch> strings;          // limited per string and per rule
};

struct CompileReport {
    bool ok = false;
    std::size_t rule_count = 0;
    std::vector<std::string> errors;     // "file:line: message"
    std::vector<std::string> warnings;
    std::vector<std::string> files;      // files that compiled and were included
};

struct Externals {
    std::string filename;
    std::string filepath;
    std::string extension;
    std::string filetype;
};

struct ScanOptions {
    int timeout_seconds = 60;
    std::size_t max_instances_per_string = 3;
    std::size_t max_strings_per_rule = 16;
    std::size_t max_rules = 256;
    Externals externals;
    CancelToken* cancel = nullptr;
};

struct ScanResult {
    std::vector<RuleMatch> matches;
    bool timed_out = false;
    bool cancelled = false;
    bool truncated = false;     // match limits were reached
    std::string error;          // libyara error (empty on success)
};

class Rules {
public:
    // Compile each file on its own first (a broken file never disables the others), then all valid
    // files together, one namespace per file. `include` directives are rejected.
    static std::shared_ptr<Rules> compile_files(const std::vector<std::filesystem::path>& files, CompileReport& report);
    static std::shared_ptr<Rules> compile_source(const std::string& source, CompileReport& report,
                                                 const std::string& ns = "default");
    static std::shared_ptr<Rules> load(const std::filesystem::path& compiled);

    ~Rules();
    Rules(const Rules&) = delete;
    Rules& operator=(const Rules&) = delete;

    void save(const std::filesystem::path& compiled) const;
    [[nodiscard]] std::size_t rule_count() const noexcept { return rule_count_; }
    // (rule identifier, metadata) for every rule in the set.
    [[nodiscard]] std::vector<std::pair<std::string, std::map<std::string, std::string>>> metadata() const;
    ScanResult scan(ByteView data, const ScanOptions& options) const;

private:
    explicit Rules(void* handle);
    void* handle_;               // YR_RULES*
    std::size_t rule_count_ = 0;
};

// Validate a directory of rule files (used before activating an offline update package).
// Detection rules must carry the metadata required by the risk engine (category, severity).
CompileReport validate_rules_dir(const std::filesystem::path& dir,
                                 const std::vector<std::string>& required_meta = {"category", "severity"});
std::vector<std::filesystem::path> rule_files_in(const std::filesystem::path& dir);
std::string version();

}  // namespace gk::yara
