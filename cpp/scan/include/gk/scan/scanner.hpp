// Scan orchestrator (Qt Core): enumeration -> cache -> isolated workers (gk-scanworker over gk-ipc) ->
// ClamAV batch -> local reputation -> folder context + risk -> SQLite.
//
// Thread model: a Scanner lives in one thread with an event loop (a QThread in the application, the
// main thread in gk-cli). start() returns after enumeration; results and progress arrive as signals.
// pause(), resume() and cancel() may be called from any thread.
#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QStringList>

#include <atomic>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include "gk/cancel.hpp"
#include "gk/db.hpp"
#include "gk/model.hpp"
#include "gk/scan_support.hpp"

namespace gk::ipc {
class HelperClient;
}

namespace gk::scan {

struct Config {
    QString dataDir;                 // database, signatures/active, temp
    QString resourceDir;             // signatures/, contracts/, third_party/ of the installation
    QString workerProgram;           // gk-scanworker(.exe)
    QString clamscan;                // empty = ClamAV unavailable
    int workers = 2;
    qint64 workerMemoryLimit = qint64(2) * 1024 * 1024 * 1024;
    int fileTimeoutMs = 180000;
    int clamavBatch = 400;
    EnumOptions enumeration;
    QJsonObject archiveLimits;       // forwarded to the worker (max_total_bytes, max_depth, ...)

    // Defaults for an installation or a development checkout (searches parents of appDir for resources).
    static Config defaults(const QString& appDir, const QString& dataDir);
    QStringList detectionRuleDirs() const;
    QString indicatorFile() const;
    QStringList iocDirs() const;
    QStringList clamavDatabaseDirs() const;
    QString componentsFile() const;
    QString catalogFile() const;
    QString databaseFile() const;
};

struct Request {
    QStringList targets;
    bool deep = true;
    QString label;
    QString origin = QStringLiteral("manual");
    bool useCache = true;
};

struct Progress {
    qint64 scanId = 0;
    QString phase;                   // enumerating | analyzing | signatures | context | saving | done
    quint64 filesTotal = 0, filesDone = 0, bytesDone = 0;
    QString current;
    quint64 threats = 0, suspicious = 0, pua = 0, errors = 0, skipped = 0, members = 0;
    bool paused = false;
};

class Scanner : public QObject {
    Q_OBJECT
public:
    explicit Scanner(Config config, QObject* parent = nullptr);
    ~Scanner() override;

    // Starts a scan. Returns the scan id (0 when it could not start; see `finished`).
    qint64 start(const Request& request);
    void pause();
    void resume();
    void cancel();
    [[nodiscard]] bool running() const { return running_; }
    [[nodiscard]] bool paused() const { return token_ && token_->paused(); }

signals:
    void progress(const gk::scan::Progress& progress);
    void fileResult(const QJsonObject& result);   // after risk assessment (FileResult contract)
    void logMessage(const QString& level, const QString& message);
    void finished(const QJsonObject& summary);    // ScanSummary-like document

private:
    struct Job {
        std::size_t candidate = 0;
        int attempts = 0;
    };
    struct Slot {
        gk::ipc::HelperClient* client = nullptr;
        qint64 callId = 0;
        std::optional<Job> job;
        std::vector<FileResult> members;
    };

    void dispatch();
    void onCallSucceeded(std::size_t slot, qint64 id, const QJsonValue& value);
    void onCallFailed(std::size_t slot, qint64 id, const QString& reason, const QString& message);
    void onEvent(std::size_t slot, qint64 id, const QString& name, const QJsonObject& data);
    void completeJob(std::size_t slot, std::vector<FileResult> results, bool fromWorker);
    void finishAnalysis();
    void runClamav();
    void finalize();
    void emitProgress(bool force = false);
    FileResult skeleton(const Candidate& c) const;
    std::string fingerprint() const;

    Config config_;
    Request request_;
    std::unique_ptr<db::Database> db_;
    std::shared_ptr<CancelToken> token_;
    std::vector<Slot> slots_;
    std::vector<Candidate> candidates_;
    std::vector<std::size_t> queue_;                 // indices into candidates_ still to analyse
    std::size_t next_ = 0;
    std::vector<FileResult> results_;                // top-level results and archive members
    std::vector<std::pair<std::string, db::PathCacheEntry>> pathCache_;
    std::vector<std::tuple<std::string, std::string, nlohmann::json>> verdicts_;
    std::vector<std::string> warnings_, limitations_;
    std::string fingerprint_;
    qint64 scanId_ = 0;
    double startedAt_ = 0;
    Progress progress_;
    qint64 lastProgressMs_ = 0;
    bool running_ = false;
    bool cancelled_ = false;
    std::size_t inFlight_ = 0;
};

}  // namespace gk::scan

Q_DECLARE_METATYPE(gk::scan::Progress)
