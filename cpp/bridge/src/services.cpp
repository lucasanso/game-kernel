#include "gk/bridge/services.hpp"

#include "gk/db.hpp"
#include "gk/error.hpp"
#include "gk/integrity.hpp"
#include "gk/quarantine.hpp"
#include "gk/text.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QMetaObject>

#include <array>

namespace gk::bridge {

namespace {

std::filesystem::path native(const QString& s) { return gk::text::utf8_path(s.toStdString()); }

QString messageOf(const std::exception& e) { return QString::fromUtf8(e.what()); }

const char* riskName(qint64 level) {
    static constexpr std::array<const char*, 6> names{"NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    return names[static_cast<std::size_t>(std::clamp<qint64>(level, 0, 5))];
}

// Scan rows keep the integer of the database and gain the level name the UI colours by.
QJsonArray withRiskNames(const QJsonArray& rows) {
    QJsonArray out;
    for (const auto& v : rows) {
        QJsonObject o = v.toObject();
        o.insert(QStringLiteral("max_risk_level"), QString::fromLatin1(riskName(o.value("max_risk").toInteger())));
        out.append(o);
    }
    return out;
}

QJsonObject progressJson(const gk::scan::Progress& p) {
    return {{"scan_id", p.scanId},
            {"phase", p.phase},
            {"files_total", static_cast<qint64>(p.filesTotal)},
            {"files_done", static_cast<qint64>(p.filesDone)},
            {"bytes_done", static_cast<qint64>(p.bytesDone)},
            {"current", p.current},
            {"threats", static_cast<qint64>(p.threats)},
            {"suspicious", static_cast<qint64>(p.suspicious)},
            {"pua", static_cast<qint64>(p.pua)},
            {"errors", static_cast<qint64>(p.errors)},
            {"skipped", static_cast<qint64>(p.skipped)},
            {"members", static_cast<qint64>(p.members)},
            {"paused", p.paused}};
}

}  // namespace

QJsonValue toQt(const nlohmann::json& value) {
    return QJsonDocument::fromJson(QByteArray::fromStdString(nlohmann::json::array({value}).dump())).array().at(0);
}

gk::scan::Config Environment::scanConfig() const { return gk::scan::Config::defaults(appDir, dataDir); }
QString Environment::databaseFile() const { return QDir(dataDir).filePath(QStringLiteral("gamekernel.db")); }
QString Environment::quarantineDir() const { return QDir(dataDir).filePath(QStringLiteral("quarantine")); }

// ============================================================================================== catalog
Catalog::Catalog(const Environment& env) {
    QFile f(env.scanConfig().catalogFile());
    if (f.open(QIODevice::ReadOnly) && f.size() < 8 * 1024 * 1024) {
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
        if (doc.isObject() && doc.object().value("format").toString() == QLatin1String("gamekernel-threat-catalog"))
            root_ = doc.object();
    }
}

QString Catalog::text(const char* section, const QString& code) const {
    const QString t = root_.value(QLatin1String(section)).toObject().value(code).toString();
    return t.isEmpty() ? code : t;   // unknown codes are shown as they are, never hidden
}

QString Catalog::classification(const QString& code) const { return text("classifications", code); }
QString Catalog::crackStatus(const QString& code) const { return text("crack_status", code); }
QString Catalog::evidenceSource(const QString& code) const { return text("evidence_sources", code); }
QJsonObject Catalog::category(const QString& code) const {
    return root_.value(QLatin1String("categories")).toObject().value(code).toObject();
}
QString Catalog::categoryLabel(const QString& code) const {
    const QString label = category(code).value("label").toString();
    return label.isEmpty() ? code : label;
}

// ================================================================================================ scans
ScanService::ScanService(Environment env, QObject* parent) : QObject(parent), env_(std::move(env)) {
    scanner_ = new gk::scan::Scanner(env_.scanConfig());
    scanner_->moveToThread(&thread_);
    connect(&thread_, &QThread::finished, scanner_, &QObject::deleteLater);
    // Signals cross threads: queued into this (UI) thread.
    connect(scanner_, &gk::scan::Scanner::progress, this, [this](const gk::scan::Progress& p) {
        if (p.scanId > 0) scanId_ = p.scanId;
        emit progressChanged(progressJson(p));
    });
    connect(scanner_, &gk::scan::Scanner::fileResult, this, &ScanService::fileAnalyzed);
    connect(scanner_, &gk::scan::Scanner::logMessage, this, &ScanService::logMessage);
    connect(scanner_, &gk::scan::Scanner::finished, this, [this](const QJsonObject& summary) {
        running_ = false;
        emit finished(summary);
    });
    thread_.setObjectName(QStringLiteral("gk-scan"));
    thread_.start();
}

ScanService::~ScanService() {
    if (running_ && scanner_) scanner_->cancel();
    thread_.quit();
    thread_.wait();
}

bool ScanService::start(const QStringList& targets, bool deep, const QString& label) {
    if (running_ || targets.isEmpty()) return false;
    gk::scan::Request request;
    for (const QString& t : targets) request.targets << QFileInfo(t).absoluteFilePath();
    request.deep = deep;
    request.label = label.isEmpty() ? QStringLiteral("Game Kernel") : label;
    request.origin = QStringLiteral("app");
    running_ = true;
    scanId_ = 0;
    gk::scan::Scanner* scanner = scanner_;
    QMetaObject::invokeMethod(
        scanner_,
        [this, scanner, request] {
            const qint64 id = scanner->start(request);   // returns after enumeration; 0 = could not start
            QMetaObject::invokeMethod(this, [this, id] {
                if (id > 0) {
                    scanId_ = id;
                    emit started(id);
                }
            }, Qt::QueuedConnection);
        },
        Qt::QueuedConnection);
    return true;
}

void ScanService::pause() { if (running_) scanner_->pause(); }
void ScanService::resume() { if (running_) scanner_->resume(); }
void ScanService::cancel() { if (running_) scanner_->cancel(); }

// ========================================================================================= history
HistoryService::HistoryService(Environment env, QObject* parent) : QObject(parent), env_(std::move(env)) {
    pool_.setMaxThreadCount(2);
}

HistoryService::~HistoryService() { pool_.waitForDone(); }

qint64 HistoryService::listScans(int limit, bool includeRealtime) {
    const qint64 request = next_++;
    const QString file = env_.databaseFile();
    pool_.start([this, request, file, limit, includeRealtime] {
        QJsonArray scans;
        QString error;
        try {
            if (QFileInfo::exists(file))   // a fresh installation has no database yet: nothing to list
                scans = withRiskNames(toQt(gk::db::Database::open_readonly(native(file))
                                               ->list_scans(limit, includeRealtime ? std::string() : std::string("realtime")))
                                          .toArray());
        } catch (const std::exception& e) {
            error = messageOf(e);
        }
        QMetaObject::invokeMethod(this, [this, request, scans, error] {
            if (error.isEmpty()) emit scansListed(request, scans);
            else emit failed(request, error);
        }, Qt::QueuedConnection);
    });
    return request;
}

qint64 HistoryService::loadScan(qint64 scanId, bool findingsOnly, int limit) {
    const qint64 request = next_++;
    const QString file = env_.databaseFile();
    pool_.start([this, request, file, scanId, findingsOnly, limit] {
        QJsonObject scan;
        QJsonArray results;
        QString error;
        try {
            const auto db = gk::db::Database::open_readonly(native(file));
            const auto row = db->scan(scanId);
            if (!row) {
                error = QStringLiteral("varredura %1 não encontrada").arg(scanId);
            } else {
                scan = toQt(*row).toObject();
                scan.insert(QStringLiteral("max_risk_level"), QString::fromLatin1(riskName(scan.value("max_risk").toInteger())));
                results = toQt(db->file_results(scanId, findingsOnly, limit)).toArray();
            }
        } catch (const std::exception& e) {
            error = messageOf(e);
        }
        QMetaObject::invokeMethod(this, [this, request, scan, results, error] {
            if (error.isEmpty()) emit scanLoaded(request, scan, results);
            else emit failed(request, error);
        }, Qt::QueuedConnection);
    });
    return request;
}

// ====================================================================================== quarantine
QuarantineService::QuarantineService(Environment env, QObject* parent) : QObject(parent), env_(std::move(env)) {
    pool_.setMaxThreadCount(1);   // vault and database operations one at a time
}

QuarantineService::~QuarantineService() { pool_.waitForDone(); }

namespace {

struct Opened {
    std::unique_ptr<gk::quarantine::Vault> vault;
    std::unique_ptr<gk::db::Database> db;
    std::unique_ptr<gk::quarantine::Manager> manager;
};

Opened openVault(const Environment& env) {
    Opened o;
    o.vault = gk::quarantine::Vault::open(native(env.quarantineDir()));
    o.db = gk::db::Database::open(native(env.databaseFile()));
    o.manager = std::make_unique<gk::quarantine::Manager>(*o.vault, *o.db);
    return o;
}

}  // namespace

qint64 QuarantineService::list(bool includeFinished) {
    const qint64 request = next_++;
    const QString file = env_.databaseFile();
    pool_.start([this, request, file, includeFinished] {
        QJsonArray items;
        QString error;
        try {
            if (QFileInfo::exists(file)) {
                const auto db = gk::db::Database::open_readonly(native(file));
                for (const auto& r : db->list_quarantine(includeFinished ? std::string() : std::string("quarantined")))
                    items.append(toQt(gk::db::to_json(r)));
            }
        } catch (const std::exception& e) {
            error = messageOf(e);
        }
        QMetaObject::invokeMethod(this, [this, request, items, error] {
            if (error.isEmpty()) emit listed(request, items);
            else emit finished(request, QStringLiteral("list"), false, {}, error);
        }, Qt::QueuedConnection);
    });
    return request;
}

qint64 QuarantineService::quarantine(const Item& item) {
    const qint64 request = next_++;
    pool_.start([this, request, item, env = env_] {
        QJsonObject result;
        QString error;
        try {
            Opened o = openVault(env);
            gk::quarantine::Request r;
            r.file = native(QFileInfo(item.path).absoluteFilePath());
            if (!item.expectedSha256.isEmpty()) r.expected_sha256 = item.expectedSha256.toStdString();
            r.reason = item.reason.isEmpty() ? std::string("manual (Game Kernel)") : item.reason.toStdString();
            r.classification = item.classification.toStdString();
            r.detection = item.detection.toStdString();
            r.risk = static_cast<gk::Risk>(std::clamp(item.risk, 0, 5));
            if (item.scanId > 0) r.scan_id = item.scanId;
            result = toQt(gk::quarantine::to_json(o.manager->quarantine(r))).toObject();
        } catch (const std::exception& e) {
            error = messageOf(e);
        }
        QMetaObject::invokeMethod(this, [this, request, result, error] {
            emit finished(request, QStringLiteral("quarantine"), error.isEmpty(), result, error);
        }, Qt::QueuedConnection);
    });
    return request;
}

qint64 QuarantineService::restore(const QString& id, const QString& destination, bool overwrite) {
    const qint64 request = next_++;
    pool_.start([this, request, id, destination, overwrite, env = env_] {
        QJsonObject result;
        QString error;
        try {
            Opened o = openVault(env);
            std::optional<std::filesystem::path> to;
            if (!destination.isEmpty()) to = native(QFileInfo(destination).absoluteFilePath());
            const auto where = o.manager->restore(id.toStdString(), to, overwrite);
            result = {{"id", id}, {"restored_to", QString::fromStdString(gk::text::path_utf8(where))}};
        } catch (const std::exception& e) {
            error = messageOf(e);
        }
        QMetaObject::invokeMethod(this, [this, request, result, error] {
            emit finished(request, QStringLiteral("restore"), error.isEmpty(), result, error);
        }, Qt::QueuedConnection);
    });
    return request;
}

qint64 QuarantineService::erase(const QString& id) {
    const qint64 request = next_++;
    pool_.start([this, request, id, env = env_] {
        QString error;
        try {
            openVault(env).manager->erase(id.toStdString());
        } catch (const std::exception& e) {
            error = messageOf(e);
        }
        QMetaObject::invokeMethod(this, [this, request, id, error] {
            emit finished(request, QStringLiteral("erase"), error.isEmpty(),
                          error.isEmpty() ? QJsonObject{{"id", id}} : QJsonObject{}, error);
        }, Qt::QueuedConnection);
    });
    return request;
}

qint64 QuarantineService::verify() {
    const qint64 request = next_++;
    pool_.start([this, request, env = env_] {
        QJsonObject result;
        QString error;
        try {
            const auto report = openVault(env).manager->verify();
            QJsonArray ok, damaged, recovered;
            for (const auto& id : report.ok) ok.append(QString::fromStdString(id));
            for (const auto& [id, why] : report.damaged)
                damaged.append(QJsonObject{{"id", QString::fromStdString(id)}, {"reason", QString::fromStdString(why)}});
            for (const auto& m : report.unknown) recovered.append(toQt(gk::quarantine::to_json(m)));
            result = {{"ok", ok}, {"damaged", damaged}, {"recovered", recovered}};
        } catch (const std::exception& e) {
            error = messageOf(e);
        }
        QMetaObject::invokeMethod(this, [this, request, result, error] {
            emit finished(request, QStringLiteral("verify"), error.isEmpty(), result, error);
        }, Qt::QueuedConnection);
    });
    return request;
}

// ======================================================================================= integrity
IntegrityService::IntegrityService(Environment env, QObject* parent) : QObject(parent), env_(std::move(env)) {
    pool_.setMaxThreadCount(1);
}

IntegrityService::~IntegrityService() { pool_.waitForDone(); }

void IntegrityService::check() {
    pool_.start([this, env = env_] {
        QJsonObject out;
        try {
            const gk::scan::Config config = env.scanConfig();
            const QString root = config.installDir.isEmpty() ? config.resourceDir : config.installDir;
            std::vector<std::filesystem::path> keyDirs;
            for (const QString& d : config.trustedKeyDirs()) keyDirs.push_back(native(d));
            gk::integrity::Verifier verifier(native(root), gk::integrity::load_trusted_keys(keyDirs));
            const auto r = verifier.check_installation();
            QJsonArray modified, missing;
            for (const auto& f : r.modified) modified.append(QString::fromStdString(f));
            for (const auto& f : r.missing) missing.append(QString::fromStdString(f));
            out = {{"ok", r.ok},
                   {"manifest_present", r.manifest_present},
                   {"signature_valid", r.signature_valid ? QJsonValue(*r.signature_valid) : QJsonValue(QJsonValue::Null)},
                   {"signer_key_id", QString::fromStdString(r.signer_key_id)},
                   {"verified", static_cast<qint64>(r.verified)},
                   {"modified", modified},
                   {"missing", missing},
                   {"detail", QString::fromStdString(r.detail)},
                   {"root", root}};
        } catch (const std::exception& e) {
            out = {{"ok", false}, {"manifest_present", false}, {"signature_valid", QJsonValue::Null},
                   {"detail", QStringLiteral("Falha ao verificar a integridade: %1").arg(messageOf(e))}};
        }
        QMetaObject::invokeMethod(this, [this, out] { emit checked(out); }, Qt::QueuedConnection);
    });
}

// ======================================================================================== real time
RealtimeService::RealtimeService(Environment env, QObject* parent) : QObject(parent), env_(std::move(env)) {
    qRegisterMetaType<gk::realtime::Settings>();
    pool_.setMaxThreadCount(1);
    monitor_ = new gk::realtime::Monitor(env_.scanConfig(), env_.quarantineDir());
    monitor_->moveToThread(&thread_);
    connect(&thread_, &QThread::finished, monitor_, &QObject::deleteLater);
    connect(monitor_, &gk::realtime::Monitor::statusChanged, this, [this](const QJsonObject& s) {
        status_ = s;
        emit statusChanged(s);
    });
    connect(monitor_, &gk::realtime::Monitor::detected, this, &RealtimeService::detected);
    connect(monitor_, &gk::realtime::Monitor::eventRecorded, this, &RealtimeService::eventRecorded);
    connect(monitor_, &gk::realtime::Monitor::batchFinished, this, &RealtimeService::batchFinished);
    connect(monitor_, &gk::realtime::Monitor::logMessage, this, &RealtimeService::logMessage);
    status_ = QJsonObject{{"enabled", false}, {"active", false}, {"supported", supported()}, {"folders", QJsonArray()},
                          {"pending", 0}, {"scanning", false}, {"batches", 0}, {"files_scanned", 0}, {"detections", 0},
                          {"quarantined", 0}};
    thread_.setObjectName(QStringLiteral("gk-realtime"));
    thread_.start();
}

RealtimeService::~RealtimeService() {
    // The monitor stops its watcher and cancels a running batch when it is destroyed in its own thread.
    thread_.quit();
    thread_.wait();
    pool_.waitForDone();
}

bool RealtimeService::supported() { return gk::realtime::DirectoryWatcher::supported(); }

void RealtimeService::apply(const gk::realtime::Settings& settings) {
    gk::realtime::Monitor* monitor = monitor_;
    QMetaObject::invokeMethod(monitor_, [monitor, settings] { monitor->apply(settings); }, Qt::QueuedConnection);
}

qint64 RealtimeService::listEvents(int limit) {
    const qint64 request = next_++;
    const QString file = env_.databaseFile();
    pool_.start([this, request, file, limit] {
        QJsonArray events;
        QString error;
        try {
            if (QFileInfo::exists(file)) {
                for (const auto& e : gk::db::Database::open_readonly(native(file))->list_realtime_events(limit)) {
                    QJsonObject o = toQt(e).toObject();
                    o.insert(QStringLiteral("risk_level"), QString::fromLatin1(riskName(o.value("risk").toInteger())));
                    events.append(o);
                }
            }
        } catch (const std::exception& e) {
            error = messageOf(e);
        }
        QMetaObject::invokeMethod(this, [this, request, events, error] {
            if (error.isEmpty()) emit eventsListed(request, events);
            else emit failed(request, error);
        }, Qt::QueuedConnection);
    });
    return request;
}

// ===================================================================================== performance
PerformanceService::PerformanceService(QObject* parent) : QObject(parent) {
    timer_ = new QTimer;
    timer_->moveToThread(&thread_);
    auto sampler = std::make_shared<gk::perf::Sampler>(8);
    tick_ = std::make_shared<std::function<void()>>([this, sampler] {   // runs in thread_
        const QJsonObject sample = gk::perf::toJson(sampler->sample());
        QMetaObject::invokeMethod(this, [this, sample] {
            if (running_) emit sampled(sample);
        }, Qt::QueuedConnection);
    });
    connect(timer_, &QTimer::timeout, timer_, [tick = tick_] { (*tick)(); });
    connect(&thread_, &QThread::finished, timer_, &QObject::deleteLater);
    thread_.setObjectName(QStringLiteral("gk-perf"));
    thread_.start();
}

PerformanceService::~PerformanceService() {
    stop();
    thread_.quit();
    thread_.wait();
}

void PerformanceService::start(int intervalMs) {
    running_ = true;
    QTimer* timer = timer_;
    const int interval = std::clamp(intervalMs, 250, 60000);
    QMetaObject::invokeMethod(timer_, [timer, interval, tick = tick_] {
        timer->start(interval);
        (*tick)();   // first sample right away
    }, Qt::QueuedConnection);
}

void PerformanceService::stop() {
    running_ = false;
    QTimer* timer = timer_;
    QMetaObject::invokeMethod(timer_, [timer] { timer->stop(); }, Qt::QueuedConnection);
}

// ======================================================================================= optimizer
OptimizerService::OptimizerService(Environment env, QObject* parent) : QObject(parent), env_(std::move(env)) {
    pool_.setMaxThreadCount(1);   // one operation at a time: a clean-up never runs beside an analysis
}

OptimizerService::~OptimizerService() {
    cancel_->store(true);
    pool_.waitForDone();
}

QStringList OptimizerService::tempRoots() const { return gk::sysopt::defaultTempRoots(env_.dataDir); }

qint64 OptimizerService::diagnose(const QStringList& folders) {
    const qint64 request = next_++;
    pool_.start([this, request, folders] {
        QJsonArray checks;
        for (const auto& c : gk::sysopt::diagnose(folders)) checks.append(gk::sysopt::toJson(c));
        QMetaObject::invokeMethod(this, [this, request, checks] { emit diagnosed(request, checks); }, Qt::QueuedConnection);
    });
    return request;
}

qint64 OptimizerService::analyzeTemp(int minAgeHours) {
    const qint64 request = next_++;
    plan_.reset();   // a clean-up always follows the analysis the user just saw
    pool_.start([this, request, minAgeHours, roots = tempRoots(), cancel = cancel_] {
        auto plan = std::make_shared<const gk::sysopt::TempPlan>(gk::sysopt::analyzeTemp(roots, minAgeHours, cancel.get()));
        const QJsonObject summary = gk::sysopt::toJson(*plan);
        QMetaObject::invokeMethod(this, [this, request, plan, summary] {
            plan_ = plan;
            emit tempAnalyzed(request, summary);
        }, Qt::QueuedConnection);
    });
    return request;
}

qint64 OptimizerService::cleanTemp() {
    const qint64 request = next_++;
    if (!plan_) {
        QMetaObject::invokeMethod(this, [this, request] {
            emit failed(request, QStringLiteral("analise os arquivos temporários antes de limpar"));
        }, Qt::QueuedConnection);
        return request;
    }
    std::shared_ptr<const gk::sysopt::TempPlan> plan = std::move(plan_);   // used once
    plan_.reset();
    pool_.start([this, request, plan, file = env_.databaseFile(), cancel = cancel_] {
        const gk::sysopt::CleanResult r = gk::sysopt::cleanTemp(*plan, cancel.get());
        QJsonObject result = gk::sysopt::toJson(r);
        try {
            const nlohmann::json detail{{"deleted", r.deleted}, {"bytes_freed", r.bytesFreed}, {"in_use", r.inUse},
                                        {"changed", r.changed}, {"dirs_removed", r.dirsRemoved}};
            gk::db::Database::open(native(file))->append_audit("optimizer.temp_clean", detail.dump(), "user");
        } catch (const std::exception& e) {
            result.insert(QStringLiteral("audit_error"), messageOf(e));
        }
        QMetaObject::invokeMethod(this, [this, request, result] { emit tempCleaned(request, result); }, Qt::QueuedConnection);
    });
    return request;
}

}  // namespace gk::bridge
