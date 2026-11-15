// Real-time protection (M11): watches the folders the user chose and scans what appears or changes there.
//
//   DirectoryWatcher (native thread) -> ChangeBatcher (stable files, gathered for a few seconds)
//     -> gk::scan::Scanner (quick mode, isolated workers, cache; origin "realtime") -> realtime_events
//     -> `detected` for findings at or above the notification level
//     -> optional automatic quarantine, only for threats confirmed by a signature, YARA rule or local IOC
//        (gk::risk::confirmed_by_signature) and never for a file the user restored from the quarantine.
//
// What it does not do (and the interface says so): it does not block a program from starting before the
// analysis — that needs a file-system filter driver — and it runs only while the application is open.
// The program's own data folder is never watched. ClamAV is not used for these small batches (loading its
// database each time would cost more than the batch); manual scans use it.
//
// Thread model: a Monitor lives in a thread with an event loop (gk::bridge::RealtimeService gives it its own
// QThread). All public methods must be called in that thread.
#pragma once

#include "gk/realtime/batcher.hpp"
#include "gk/realtime/watcher.hpp"
#include "gk/scan/scanner.hpp"

#include <QElapsedTimer>
#include <QHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QStringList>

#include <memory>

class QTimer;

namespace gk::db {
class Database;
}

namespace gk::realtime {

struct Settings {
    bool enabled = false;
    QStringList folders;
    int notifyMinRisk = 3;        // RiskLevel integer: MEDIUM
    bool autoQuarantine = false;
    int batchSeconds = 8;         // 2..300
    int stableSeconds = 2;        // 1..60
    int workers = 1;              // 1..8
    QStringList excludedPaths;    // scan.excluded_paths
    bool operator==(const Settings&) const = default;
};

class Monitor : public QObject {
    Q_OBJECT
public:
    Monitor(gk::scan::Config config, QString quarantineDir, QObject* parent = nullptr);
    ~Monitor() override;

    // Starts, reconfigures or stops (enabled = false, or no folder) the protection.
    void apply(const Settings& settings);
    void stop();
    [[nodiscard]] QJsonObject status() const;
    [[nodiscard]] bool active() const { return watcher_->active(); }
    void setTickInterval(int ms);   // how often pending changes are looked at (default 1 s)
    // Scan settings for the next batches (the next batch uses a scanner built with them).
    void setScanConfig(gk::scan::Config config);

signals:
    // {enabled, active, supported, folders:[{path, watching, error}], pending, scanning, batches, files_scanned,
    //  detections, quarantined, last_scan_id, last_batch_at, collapses, notify_min_risk, auto_quarantine}
    void statusChanged(const QJsonObject& status);
    // A finding at or above the notification level: {path, risk, risk_level, classification, detection,
    // category, sha256, scan_id, action (notified | quarantined | quarantine_failed | restored_before), message}
    void detected(const QJsonObject& detection);
    void eventRecorded(const QJsonObject& event);    // every row written to realtime_events
    void batchFinished(const QJsonObject& summary);  // ScanSummary of one batch
    void logMessage(const QString& level, const QString& message);

private:
    struct Top;
    void onChanges(const QList<gk::realtime::Change>& changes);
    void onOverflow(const QString& root);
    void onFailed(const QString& root, const QString& message);
    void tick();
    void startBatch(const Batch& batch);
    void onBatchFinished(const QJsonObject& summary);
    void handle(const Top& top, qint64 scanId);
    void record(const QString& path, const QString& event, const QString& sha256, int risk, const QString& classification,
                qint64 scanId, const QJsonObject& detail);
    bool restoredBefore(const QString& sha256);
    gk::db::Database* database();
    void ensureScanner();
    void publish();

    gk::scan::Config config_;
    QString quarantineDir_;
    Settings settings_;
    DirectoryWatcher* watcher_;
    gk::scan::Scanner* scanner_ = nullptr;
    int scannerWorkers_ = 0;
    bool configChanged_ = false;
    QTimer* timer_;
    QElapsedTimer clock_;
    ChangeBatcher batcher_;
    QHash<QString, QString> folderErrors_;   // requested folder -> why it is not watched
    QList<QJsonObject> results_;             // results of the batch being scanned
    Batch current_;
    bool scanning_ = false;
    std::unique_ptr<gk::db::Database> db_;
    qint64 batches_ = 0, filesScanned_ = 0, detections_ = 0, quarantined_ = 0, lastScanId_ = 0;
    double lastBatchAt_ = 0;
};

}  // namespace gk::realtime

Q_DECLARE_METATYPE(gk::realtime::Settings)
