// Qt service layer between the desktop application and the C++ core (M13). Every service is a QObject that
// lives in the UI thread and never blocks it: scans run in a dedicated thread, database reads and vault
// operations on background workers, and results come back as signals carrying JSON (the same documents the
// core writes: FileResult, ScanSummary, quarantine records). The UI never touches gk_core directly.
#pragma once

#include <QJsonArray>
#include <QJsonObject>
#include <QObject>
#include <QStringList>
#include <QThread>
#include <QThreadPool>

#include <memory>

#include "gk/scan/scanner.hpp"

namespace gk::bridge {

// Where the installation and the user's data are. The scan configuration (resources, worker, ClamAV,
// integrity root) is derived from them exactly as gk-cli does.
struct Environment {
    QString appDir;     // folder of the running executable
    QString dataDir;    // the application's data folder (settings, database, reports, quarantine)

    [[nodiscard]] gk::scan::Config scanConfig() const;
    [[nodiscard]] QString databaseFile() const;     // <data>/gamekernel.db
    [[nodiscard]] QString quarantineDir() const;    // <data>/quarantine
};

// nlohmann::json <-> Qt JSON (exact round trip through the text form).
QJsonValue toQt(const nlohmann::json& value);

// ------------------------------------------------------------------------------------------- scans
class ScanService : public QObject {
    Q_OBJECT
public:
    explicit ScanService(Environment env, QObject* parent = nullptr);
    ~ScanService() override;   // cancels a running scan and waits for its thread

    // false (nothing started) when a scan is already running or there is no target.
    bool start(const QStringList& targets, bool deep, const QString& label = {});
    void pause();
    void resume();
    void cancel();
    [[nodiscard]] bool running() const { return running_; }
    [[nodiscard]] qint64 currentScanId() const { return scanId_; }

signals:
    void started(qint64 scanId);
    // {scan_id, phase, files_total, files_done, bytes_done, current, threats, suspicious, pua, errors, skipped,
    //  members, paused}
    void progressChanged(const QJsonObject& progress);
    void fileAnalyzed(const QJsonObject& result);      // FileResult after risk assessment
    void logMessage(const QString& level, const QString& message);
    void finished(const QJsonObject& summary);         // status: completed | cancelled | failed

private:
    Environment env_;
    QThread thread_;
    gk::scan::Scanner* scanner_ = nullptr;             // lives in thread_
    bool running_ = false;
    qint64 scanId_ = 0;
};

// ----------------------------------------------------------------------------------- history/results
class HistoryService : public QObject {
    Q_OBJECT
public:
    explicit HistoryService(Environment env, QObject* parent = nullptr);
    ~HistoryService() override;

    // Asynchronous; each returns a request id echoed by the signals. A missing database is not an error
    // (fresh installation): the lists are empty.
    qint64 listScans(int limit = 200);
    qint64 loadScan(qint64 scanId, bool findingsOnly = true, int limit = 5000);

signals:
    void scansListed(qint64 request, const QJsonArray& scans);
    void scanLoaded(qint64 request, const QJsonObject& scan, const QJsonArray& results);
    void failed(qint64 request, const QString& message);

private:
    Environment env_;
    QThreadPool pool_;
    qint64 next_ = 1;
};

// ------------------------------------------------------------------------------------------ quarantine
class QuarantineService : public QObject {
    Q_OBJECT
public:
    explicit QuarantineService(Environment env, QObject* parent = nullptr);
    ~QuarantineService() override;

    struct Item {
        QString path;
        QString expectedSha256;    // refuse when the file changed since it was analysed
        QString reason, classification, detection;
        int risk = 0;              // RiskLevel integer
        qint64 scanId = 0;         // 0 = none
    };

    // All operations run one at a time on a background worker (vault + database + audit log).
    qint64 list(bool includeFinished = false);       // also restored/deleted items
    qint64 quarantine(const Item& item);
    qint64 restore(const QString& id, const QString& destination = {}, bool overwrite = false);
    qint64 erase(const QString& id);
    qint64 verify();

signals:
    void listed(qint64 request, const QJsonArray& items);
    // ok=false: result is empty and message explains (pt-BR); kind: quarantine | restore | erase | verify
    void finished(qint64 request, const QString& kind, bool ok, const QJsonObject& result, const QString& message);

private:
    Environment env_;
    QThreadPool pool_;
    qint64 next_ = 1;
};

// ------------------------------------------------------------------------------------------- integrity
class IntegrityService : public QObject {
    Q_OBJECT
public:
    explicit IntegrityService(Environment env, QObject* parent = nullptr);
    ~IntegrityService() override;
    void check();   // re-hashes every file of the installation manifest in the background

signals:
    // {ok, manifest_present, signature_valid (bool|null), signer_key_id, verified, modified[], missing[], detail}
    void checked(const QJsonObject& report);

private:
    Environment env_;
    QThreadPool pool_;
};

}  // namespace gk::bridge
