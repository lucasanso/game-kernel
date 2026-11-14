// Building blocks of a scan that do not need Qt: enumeration, local reputation (IOC), ClamAV output parsing.
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "gk/cancel.hpp"
#include "gk/filetype.hpp"
#include "gk/model.hpp"

namespace gk::scan {

// ---- enumeration ----------------------------------------------------------------------------
struct EnumOptions {
    bool deep = true;
    FileTypeFilter types;
    std::vector<std::string> excluded_paths;        // prefixes, case-insensitive
    std::vector<std::string> excluded_extensions;   // ".pak"
    std::uint64_t max_analysis_bytes = 512ull << 20;
};

struct Candidate {
    std::filesystem::path path;
    std::string path_utf8;
    std::uint64_t size = 0;
    std::int64_t mtime_ns = 0;
    TypeInfo type;
    int priority = 8;
    bool selected = true;         // analysed by the workers
    std::string skip_reason;      // why it was not selected (shown to the user)
};

struct EnumResult {
    std::vector<Candidate> files;
    std::vector<std::string> errors;     // unreadable directories/files
    std::uint64_t total_bytes = 0;
};

// Walks the targets (files and/or folders) without following symbolic links or junctions.
EnumResult enumerate(const std::vector<std::filesystem::path>& targets, const EnumOptions& options,
                     CancelToken* cancel = nullptr, const std::function<void(std::size_t)>& progress = {});

// ---- local reputation (IOC files) ---------------------------------------------------------------
struct IocEntry {
    std::string verdict;          // bad | good
    std::string name, category, severity, source, note;
};

class IocDb {
public:
    // Loads every gamekernel-ioc JSON file of the directories (later directories override earlier ones).
    static IocDb load(const std::vector<std::filesystem::path>& dirs, std::vector<std::string>* errors = nullptr);
    [[nodiscard]] const IocEntry* find(const std::string& sha256) const;
    [[nodiscard]] std::size_t size() const { return entries_.size(); }
    [[nodiscard]] const std::string& version() const { return version_; }

private:
    std::map<std::string, IocEntry> entries_;
    std::string version_;
};

// Evidence for a reputation hit (local IOC files or the user's own reputation table).
std::optional<Evidence> reputation_evidence(const std::string& verdict, const std::string& name,
                                            const std::string& category, const std::string& severity,
                                            const std::string& origin);

// ---- ClamAV ------------------------------------------------------------------------------------
// Parses `clamscan --no-summary --stdout` output: "<path>: <signature> FOUND" lines -> path -> signature.
std::map<std::string, std::string> parse_clamscan(const std::string& output);
// Evidence for a ClamAV detection, classifying PUA / heuristic / test signatures by their names.
Evidence clamav_evidence(const std::string& signature, bool inside_archive);

}  // namespace gk::scan
