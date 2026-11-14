// SQLite storage of the application (writer side). Same schema as gamekernel/database/db.py
// (contracts/schema.sql, embedded at build time) so Python tools and reports read what C++ writes.
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "gk/model.hpp"

struct sqlite3;

namespace gk::db {

struct PathCacheEntry {
    std::uint64_t size = 0;
    std::int64_t mtime_ns = 0;
    std::string sha256;
    std::string md5;
};

struct ScanCounters {
    std::uint64_t files_found = 0, files_analyzed = 0, files_skipped = 0, files_errors = 0, members_analyzed = 0;
    std::uint64_t threats = 0, suspicious = 0, pua = 0, bytes_scanned = 0;
    Risk max_risk = Risk::None;
};

struct Reputation {
    std::string verdict;   // good | bad
    std::string name, source, note;
};

// Row of the `quarantine` table (same columns the Python layer reads).
struct QuarantineRecord {
    std::string id, original_path, sha256;
    std::uint64_t size = 0;
    double quarantined_at = 0;
    std::string reason, classification, detection;
    int risk = 0;                          // RiskLevel integer (NONE=0 .. CRITICAL=5)
    std::optional<std::int64_t> scan_id;
    std::string stored_name;
    std::string status;                    // quarantined | restored | deleted
    nlohmann::json meta = nlohmann::json::object();
};

class Database {
public:
    // Opens (creating if needed), runs quick_check, moves a corrupt file aside and recreates it.
    static std::unique_ptr<Database> open(const std::filesystem::path& file);
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    [[nodiscard]] const std::optional<std::filesystem::path>& recovered_from() const { return recovered_from_; }

    std::int64_t create_scan(const std::string& mode, const nlohmann::json& targets, const nlohmann::json& options,
                             const std::string& fingerprint, const std::string& origin, const std::string& label);
    void update_scan(std::int64_t scan_id, const ScanCounters& counters, const std::string& status);
    void finish_scan(std::int64_t scan_id, const std::string& status, const ScanCounters& counters,
                     const nlohmann::json& summary, const std::string& error);
    int mark_interrupted_scans();

    void add_file_results(std::int64_t scan_id, const std::vector<FileResult>& results);

    std::optional<PathCacheEntry> path_cache(const std::string& path);
    void put_path_cache(const std::vector<std::pair<std::string, PathCacheEntry>>& entries);
    std::optional<nlohmann::json> verdict(const std::string& sha256, const std::string& fingerprint);
    void put_verdicts(const std::vector<std::tuple<std::string, std::string, nlohmann::json>>& entries);
    std::optional<Reputation> reputation(const std::string& sha256);

    void append_audit(const std::string& action, const std::string& detail, const std::string& actor);

    // Quarantine bookkeeping (the encrypted items themselves live in gk::quarantine::Vault).
    void add_quarantine_item(const QuarantineRecord& record);
    void remove_quarantine_item(const std::string& id);          // rollback of a failed quarantine only
    void update_quarantine_status(const std::string& id, const std::string& status);
    std::optional<QuarantineRecord> quarantine_item(const std::string& id);
    std::vector<QuarantineRecord> list_quarantine(const std::string& status);   // empty status = all
    void add_quarantine_event(const std::string& id, const std::string& action, const std::string& detail);

private:
    explicit Database(sqlite3* handle) : db_(handle) {}
    void exec(const char* sql);
    sqlite3* db_;
    std::optional<std::filesystem::path> recovered_from_;
};

}  // namespace gk::db
