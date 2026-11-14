#include "gk/db.hpp"
#include "gk/text.hpp"

#include <sqlite3.h>

#include <chrono>
#include <cmath>
#include <cstdio>
#include <ctime>

#include "gk/error.hpp"
#include "gk/hash.hpp"
#include "gk/schema.hpp"
#include "gk/serialize.hpp"

namespace gk::db {

namespace {

using nlohmann::json;

double now() {
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK) {
            throw Error(ErrorCode::Internal, std::string("SQLite: ") + sqlite3_errmsg(db));
        }
    }
    ~Stmt() { sqlite3_finalize(stmt_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    Stmt& bind(int i, const std::string& v) {
        sqlite3_bind_text(stmt_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
        return *this;
    }
    Stmt& bind(int i, std::int64_t v) {
        sqlite3_bind_int64(stmt_, i, v);
        return *this;
    }
    Stmt& bind(int i, double v) {
        sqlite3_bind_double(stmt_, i, v);
        return *this;
    }
    Stmt& bind_null(int i) {
        sqlite3_bind_null(stmt_, i);
        return *this;
    }
    Stmt& bind_opt(int i, const std::optional<std::string>& v) { return v ? bind(i, *v) : bind_null(i); }

    // Returns true when a row is available.
    bool step() {
        const int rc = sqlite3_step(stmt_);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        throw Error(ErrorCode::Internal, std::string("SQLite: ") + sqlite3_errmsg(db_));
    }
    void reset() {
        sqlite3_reset(stmt_);
        sqlite3_clear_bindings(stmt_);
    }
    std::string text(int col) {
        const auto* p = reinterpret_cast<const char*>(sqlite3_column_text(stmt_, col));
        return p ? std::string(p, static_cast<std::size_t>(sqlite3_column_bytes(stmt_, col))) : std::string();
    }
    std::int64_t integer(int col) { return sqlite3_column_int64(stmt_, col); }
    double real(int col) { return sqlite3_column_double(stmt_, col); }
    bool is_null(int col) { return sqlite3_column_type(stmt_, col) == SQLITE_NULL; }

private:
    sqlite3* db_;
    sqlite3_stmt* stmt_ = nullptr;
};

class Transaction {
public:
    explicit Transaction(sqlite3* db) : db_(db) { run("BEGIN IMMEDIATE"); }
    ~Transaction() {
        if (!done_) sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
    }
    void commit() {
        run("COMMIT");
        done_ = true;
    }

private:
    void run(const char* sql) {
        char* err = nullptr;
        if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
            std::string message = err ? err : "erro";
            sqlite3_free(err);
            throw Error(ErrorCode::Internal, "SQLite: " + message);
        }
    }
    sqlite3* db_;
    bool done_ = false;
};

sqlite3* open_handle(const std::filesystem::path& file) {
    sqlite3* db = nullptr;
    const int rc = sqlite3_open_v2(text::path_utf8(file).c_str(), &db,
                                   SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK) {
        std::string msg = db ? sqlite3_errmsg(db) : "falha ao abrir";
        sqlite3_close(db);
        throw Error(ErrorCode::FileAccess, "não foi possível abrir o banco: " + msg);
    }
    sqlite3_busy_timeout(db, 30000);
    return db;
}

bool healthy(sqlite3* db) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &stmt, nullptr) != SQLITE_OK) return false;
    bool ok = sqlite3_step(stmt) == SQLITE_ROW &&
              std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))) == "ok";
    sqlite3_finalize(stmt);
    return ok;
}

// Same rule as gamekernel/database/db.py::_needs_full_json.
bool needs_full_json(const FileResult& r) {
    return !r.evidences.empty() || r.status != AnalysisStatus::Complete ||
           (r.classification != Classification::Unknown && r.classification != Classification::KnownLegit) ||
           r.crack_status != CrackStatus::None || !r.status_reasons.empty();
}

}  // namespace

std::unique_ptr<Database> Database::open(const std::filesystem::path& file) {
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    sqlite3* handle = open_handle(file);
    std::optional<std::filesystem::path> recovered;
    if (!healthy(handle)) {
        sqlite3_close(handle);
        char stamp[32];
        const std::time_t t = std::time(nullptr);
        std::tm local{};
#ifdef _WIN32
        localtime_s(&local, &t);
#else
        localtime_r(&t, &local);
#endif
        std::strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", &local);
        std::filesystem::path backup = file;
        backup += std::string(".corrupt-") + stamp;
        for (const char* suffix : {"", "-wal", "-shm"}) {
            std::filesystem::path src = file;
            src += suffix;
            std::filesystem::path dst = backup;
            dst += suffix;
            if (std::filesystem::exists(src, ec)) {
                std::filesystem::rename(src, dst, ec);
                if (ec) std::filesystem::remove(src, ec);
            }
        }
        recovered = backup;
        handle = open_handle(file);
    }
    std::unique_ptr<Database> db(new Database(handle));
    db->recovered_from_ = recovered;
    db->exec("PRAGMA journal_mode=WAL");
    db->exec("PRAGMA synchronous=NORMAL");
    db->exec("PRAGMA foreign_keys=ON");
    db->exec(kSchemaSql);
    {
        Stmt s(handle, "SELECT value FROM meta WHERE key='schema_version'");
        if (!s.step()) {
            Stmt ins(handle, "INSERT INTO meta(key, value) VALUES('schema_version', ?)");
            ins.bind(1, std::to_string(kSchemaVersion));
            ins.step();
        } else if (std::stoi(s.text(0)) > kSchemaVersion) {
            throw Error(ErrorCode::InvalidFormat, "banco criado por uma versão mais nova do Game Kernel");
        }
    }
    return db;
}

Database::~Database() { sqlite3_close(db_); }

void Database::exec(const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string message = err ? err : "erro";
        sqlite3_free(err);
        throw Error(ErrorCode::Internal, "SQLite: " + message);
    }
}

std::int64_t Database::create_scan(const std::string& mode, const json& targets, const json& options,
                                   const std::string& fingerprint, const std::string& origin, const std::string& label) {
    Stmt s(db_, "INSERT INTO scans(started_at, mode, origin, label, targets, status, options, engine_fingerprint)"
                " VALUES(?,?,?,?,?,'running',?,?)");
    s.bind(1, now()).bind(2, mode).bind(3, origin).bind(4, label).bind(5, targets.dump()).bind(6, options.dump()).bind(7, fingerprint);
    s.step();
    return sqlite3_last_insert_rowid(db_);
}

void Database::update_scan(std::int64_t id, const ScanCounters& c, const std::string& status) {
    Stmt s(db_, "UPDATE scans SET status=?, files_found=?, files_analyzed=?, files_skipped=?, files_errors=?,"
                " members_analyzed=?, threats=?, suspicious=?, pua=?, bytes_scanned=?, max_risk=? WHERE id=?");
    s.bind(1, status)
        .bind(2, static_cast<std::int64_t>(c.files_found))
        .bind(3, static_cast<std::int64_t>(c.files_analyzed))
        .bind(4, static_cast<std::int64_t>(c.files_skipped))
        .bind(5, static_cast<std::int64_t>(c.files_errors))
        .bind(6, static_cast<std::int64_t>(c.members_analyzed))
        .bind(7, static_cast<std::int64_t>(c.threats))
        .bind(8, static_cast<std::int64_t>(c.suspicious))
        .bind(9, static_cast<std::int64_t>(c.pua))
        .bind(10, static_cast<std::int64_t>(c.bytes_scanned))
        .bind(11, static_cast<std::int64_t>(c.max_risk))
        .bind(12, id);
    s.step();
}

void Database::finish_scan(std::int64_t id, const std::string& status, const ScanCounters& c, const json& summary,
                           const std::string& error) {
    update_scan(id, c, status);
    Stmt s(db_, "UPDATE scans SET finished_at=?, summary=?, error=? WHERE id=?");
    s.bind(1, now()).bind(2, summary.dump(-1, ' ', false, json::error_handler_t::replace));
    if (error.empty()) {
        s.bind_null(3);
    } else {
        s.bind(3, error);
    }
    s.bind(4, id);
    s.step();
}

int Database::mark_interrupted_scans() {
    Stmt s(db_, "UPDATE scans SET status='interrupted', finished_at=? WHERE status IN ('running','paused')");
    s.bind(1, now());
    s.step();
    return sqlite3_changes(db_);
}

void Database::add_file_results(std::int64_t scan_id, const std::vector<FileResult>& results) {
    Transaction tx(db_);
    Stmt s(db_, "INSERT INTO scan_files(scan_id, path, container, sha256, size, file_type, status, risk, classification,"
                " crack_status, primary_category, possible_fp, analyzed_at, result_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    for (const FileResult& r : results) {
        s.bind(1, scan_id)
            .bind(2, r.path)
            .bind_opt(3, r.container)
            .bind_opt(4, r.sha256)
            .bind(5, static_cast<std::int64_t>(r.size))
            .bind(6, r.file_type)
            .bind(7, std::string(value_of(r.status)))
            .bind(8, static_cast<std::int64_t>(r.risk))
            .bind(9, std::string(value_of(r.classification)))
            .bind(10, std::string(value_of(r.crack_status)))
            .bind_opt(11, r.primary_category)
            .bind(12, static_cast<std::int64_t>(r.possible_false_positive ? 1 : 0))
            .bind(13, r.analyzed_at > 0 ? r.analyzed_at : now());
        if (needs_full_json(r)) {
            s.bind(14, to_json(r).dump(-1, ' ', false, json::error_handler_t::replace));
        } else {
            s.bind_null(14);
        }
        s.step();
        s.reset();
    }
    tx.commit();
}

std::optional<PathCacheEntry> Database::path_cache(const std::string& path) {
    Stmt s(db_, "SELECT size, mtime_ns, sha256, md5 FROM path_cache WHERE path=?");
    s.bind(1, path);
    if (!s.step()) return std::nullopt;
    return PathCacheEntry{static_cast<std::uint64_t>(s.integer(0)), s.integer(1), s.text(2), s.text(3)};
}

void Database::put_path_cache(const std::vector<std::pair<std::string, PathCacheEntry>>& entries) {
    Transaction tx(db_);
    Stmt s(db_, "INSERT OR REPLACE INTO path_cache(path, size, mtime_ns, sha256, md5, updated_at) VALUES(?,?,?,?,?,?)");
    for (const auto& [path, e] : entries) {
        s.bind(1, path).bind(2, static_cast<std::int64_t>(e.size)).bind(3, e.mtime_ns).bind(4, e.sha256).bind(5, e.md5).bind(6, now());
        s.step();
        s.reset();
    }
    tx.commit();
}

std::optional<json> Database::verdict(const std::string& sha256, const std::string& fingerprint) {
    Stmt s(db_, "SELECT payload FROM verdict_cache WHERE sha256=? AND fingerprint=?");
    s.bind(1, sha256).bind(2, fingerprint);
    if (!s.step()) return std::nullopt;
    try {
        return json::parse(s.text(0));
    } catch (const json::exception&) {
        return std::nullopt;
    }
}

void Database::put_verdicts(const std::vector<std::tuple<std::string, std::string, json>>& entries) {
    Transaction tx(db_);
    Stmt s(db_, "INSERT OR REPLACE INTO verdict_cache(sha256, fingerprint, payload, updated_at) VALUES(?,?,?,?)");
    for (const auto& [sha, fp, payload] : entries) {
        s.bind(1, sha).bind(2, fp).bind(3, payload.dump(-1, ' ', false, json::error_handler_t::replace)).bind(4, now());
        s.step();
        s.reset();
    }
    tx.commit();
}

std::optional<Reputation> Database::reputation(const std::string& sha256) {
    Stmt s(db_, "SELECT verdict, name, source, note FROM reputation WHERE sha256=?");
    s.bind(1, sha256);
    if (!s.step()) return std::nullopt;
    return Reputation{s.text(0), s.text(1), s.text(2), s.text(3)};
}

void Database::append_audit(const std::string& action, const std::string& detail, const std::string& actor) {
    // Hash chain identical to gamekernel/database/db.py::_audit_hash (JSON of [prev, at, actor, action, detail]).
    Transaction tx(db_);
    std::string prev(64, '0');
    {
        Stmt s(db_, "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1");
        if (s.step()) prev = s.text(0);
    }
    const double at = std::round(now() * 1e6) / 1e6;
    // Python json.dumps uses ", " between items: build the identical text so both sides compute the same hash.
    const std::string payload = "[" + json(prev).dump() + ", " + json(at).dump() + ", " + json(actor).dump() + ", " +
                                json(action).dump() + ", " + json(detail).dump() + "]";
    Stmt ins(db_, "INSERT INTO audit_log(at, actor, action, detail, prev_hash, hash) VALUES(?,?,?,?,?,?)");
    ins.bind(1, at).bind(2, actor).bind(3, action).bind(4, detail).bind(5, prev).bind(6, sha256_hex(ByteView(payload)));
    ins.step();
    tx.commit();
}

// ------------------------------------------------------------------ quarantine

namespace {
constexpr const char* kQuarantineColumns =
    "id, original_path, sha256, size, quarantined_at, reason, risk, classification, detection, scan_id, stored_name, "
    "status, meta_json";

QuarantineRecord quarantine_row(Stmt& s) {
    QuarantineRecord r;
    r.id = s.text(0);
    r.original_path = s.text(1);
    r.sha256 = s.text(2);
    r.size = static_cast<std::uint64_t>(s.integer(3));
    r.quarantined_at = s.real(4);
    r.reason = s.text(5);
    r.risk = static_cast<int>(s.integer(6));
    r.classification = s.text(7);
    r.detection = s.text(8);
    if (!s.is_null(9)) r.scan_id = s.integer(9);
    r.stored_name = s.text(10);
    r.status = s.text(11);
    const std::string meta = s.text(12);
    r.meta = meta.empty() ? json::object() : json::parse(meta, nullptr, false);
    if (r.meta.is_discarded()) r.meta = json::object();
    return r;
}
}  // namespace

void Database::add_quarantine_item(const QuarantineRecord& r) {
    Stmt s(db_, (std::string("INSERT INTO quarantine(") + kQuarantineColumns + ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)").c_str());
    s.bind(1, r.id).bind(2, r.original_path).bind(3, r.sha256).bind(4, static_cast<std::int64_t>(r.size));
    s.bind(5, r.quarantined_at).bind(6, r.reason).bind(7, static_cast<std::int64_t>(r.risk)).bind(8, r.classification);
    s.bind(9, r.detection);
    if (r.scan_id) {
        s.bind(10, *r.scan_id);
    } else {
        s.bind_null(10);
    }
    s.bind(11, r.stored_name).bind(12, r.status).bind(13, r.meta.dump());
    s.step();
}

void Database::remove_quarantine_item(const std::string& id) {
    Stmt s(db_, "DELETE FROM quarantine WHERE id=?");
    s.bind(1, id);
    s.step();
}

void Database::update_quarantine_status(const std::string& id, const std::string& status) {
    Stmt s(db_, "UPDATE quarantine SET status=? WHERE id=?");
    s.bind(1, status).bind(2, id);
    s.step();
}

std::optional<QuarantineRecord> Database::quarantine_item(const std::string& id) {
    Stmt s(db_, (std::string("SELECT ") + kQuarantineColumns + " FROM quarantine WHERE id=?").c_str());
    s.bind(1, id);
    if (!s.step()) return std::nullopt;
    return quarantine_row(s);
}

std::vector<QuarantineRecord> Database::list_quarantine(const std::string& status) {
    std::vector<QuarantineRecord> out;
    Stmt s(db_, (std::string("SELECT ") + kQuarantineColumns + " FROM quarantine" +
                 (status.empty() ? "" : " WHERE status=?") + " ORDER BY quarantined_at DESC").c_str());
    if (!status.empty()) s.bind(1, status);
    while (s.step()) out.push_back(quarantine_row(s));
    return out;
}

void Database::add_quarantine_event(const std::string& id, const std::string& action, const std::string& detail) {
    Stmt s(db_, "INSERT INTO quarantine_events(item_id, action, at, detail) VALUES(?,?,?,?)");
    s.bind(1, id).bind(2, action).bind(3, now()).bind(4, detail);
    s.step();
}

}  // namespace gk::db
