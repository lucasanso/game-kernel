#include "gk/realtime/monitor.hpp"

#include "gk/db.hpp"
#include "gk/quarantine.hpp"
#include "gk/risk.hpp"
#include "gk/serialize.hpp"
#include "gk/text.hpp"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QTimer>

#include <algorithm>
#include <array>
#include <stdexcept>

namespace gk::realtime {

namespace {

constexpr std::array<const char*, 6> kRiskNames{"NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};

int riskOf(const QJsonValue& v) {
    if (v.isString()) {
        for (std::size_t i = 0; i < kRiskNames.size(); ++i)
            if (v.toString() == QLatin1String(kRiskNames[i])) return static_cast<int>(i);
        return 0;
    }
    return std::clamp(v.toInt(), 0, 5);
}

QString riskName(int risk) { return QString::fromLatin1(kRiskNames[static_cast<std::size_t>(std::clamp(risk, 0, 5))]); }

double nowSeconds() { return static_cast<double>(QDateTime::currentMSecsSinceEpoch()) / 1000.0; }

std::filesystem::path native(const QString& s) { return gk::text::utf8_path(s.toStdString()); }

nlohmann::json toCore(const QJsonObject& o) {
    return nlohmann::json::parse(QJsonDocument(o).toJson(QJsonDocument::Compact).toStdString(), nullptr, false);
}

// The evidence a person reads first: the highest effective severity, signatures before heuristics on ties.
QString detectionOf(const QJsonObject& result) {
    QString best;
    int bestRisk = -1;
    for (const auto& v : result.value("evidences").toArray()) {
        const QJsonObject e = v.toObject();
        const int r = riskOf(e.value("adjusted_severity").isString() ? e.value("adjusted_severity") : e.value("severity"));
        if (r > bestRisk) {
            bestRisk = r;
            best = e.value("title").toString();
        }
    }
    return best;
}

bool confirmed(const QJsonObject& result) {
    const nlohmann::json j = toCore(result);
    if (j.is_discarded()) return false;
    try {
        return gk::risk::confirmed_by_signature(gk::file_result_from_json(j));
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

struct Monitor::Top {
    QString path;
    QJsonObject self;    // the file's own result (archives: the container)
    QJsonObject worst;   // highest risk among the file and its members
    int risk = 0;
    bool confirmed = false;
};

Monitor::Monitor(gk::scan::Config config, QString quarantineDir, QObject* parent)
    : QObject(parent), config_(std::move(config)), quarantineDir_(std::move(quarantineDir)) {
    // Small, frequent batches: starting clamscan (and loading its database) for each would cost more than the
    // batch itself. Manual scans keep using ClamAV; the batch summary lists the limitation.
    config_.clamscan.clear();
    watcher_ = new DirectoryWatcher(this);
    timer_ = new QTimer(this);
    timer_->setInterval(1000);
    connect(watcher_, &DirectoryWatcher::changes, this, &Monitor::onChanges);
    connect(watcher_, &DirectoryWatcher::overflow, this, &Monitor::onOverflow);
    connect(watcher_, &DirectoryWatcher::failed, this, &Monitor::onFailed);
    connect(timer_, &QTimer::timeout, this, &Monitor::tick);
    clock_.start();
}

Monitor::~Monitor() {
    timer_->stop();
    watcher_->stop();
    if (scanner_ && scanning_) scanner_->cancel();
}

void Monitor::setTickInterval(int ms) { timer_->setInterval(std::max(10, ms)); }

void Monitor::setScanConfig(gk::scan::Config config) {
    config.clamscan.clear();   // see the constructor
    config.dataDir = config_.dataDir;
    config_ = std::move(config);
    configChanged_ = true;
}

void Monitor::apply(const Settings& requested) {
    Settings s = requested;
    s.batchSeconds = std::clamp(s.batchSeconds, 2, 300);
    s.stableSeconds = std::clamp(s.stableSeconds, 1, 60);
    s.workers = std::clamp(s.workers, 1, 8);
    s.notifyMinRisk = std::clamp(s.notifyMinRisk, 1, 5);
    const bool restart = s.enabled != settings_.enabled || s.folders != settings_.folders ||
                         s.excludedPaths != settings_.excludedPaths || (s.enabled && !watcher_->active());
    settings_ = s;

    BatcherOptions options;
    options.stableMs = qint64(s.stableSeconds) * 1000;
    options.batchMs = qint64(s.batchSeconds) * 1000;
    batcher_.setOptions(options);
    // The program's own files (database, quarantine vault, temporary files, installed signatures) are never
    // watched: writing them must not trigger scans, and the vault must not be scanned.
    QStringList excluded = s.excludedPaths;
    excluded << config_.dataDir << quarantineDir_;
    batcher_.setExcluded(excluded);

    if (!s.enabled || s.folders.isEmpty()) {
        stop();
        publish();
        return;
    }
    if (restart) {
        timer_->stop();
        folderErrors_.clear();
        QStringList folders;
        for (const QString& f : s.folders) {
            const QString clean = DirectoryWatcher::cleanFolder(f);
            if (batcher_.excluded(clean)) {
                folderErrors_.insert(clean, QStringLiteral("pasta de dados do Game Kernel ou excluída nas configurações: não é observada"));
                continue;
            }
            folders << clean;
        }
        for (const auto& refusal : watcher_->start(folders)) folderErrors_.insert(refusal.folder, refusal.reason);
        batcher_.clear();
        batcher_.setRoots(watcher_->roots());
        if (watcher_->active()) {
            timer_->start();
            emit logMessage(QStringLiteral("info"), QStringLiteral("Proteção em tempo real ativa em %1 pasta(s).").arg(watcher_->roots().size()));
        }
        for (auto it = folderErrors_.cbegin(); it != folderErrors_.cend(); ++it) {
            emit logMessage(QStringLiteral("warning"), QStringLiteral("Proteção em tempo real: %1 não é observada: %2")
                                                           .arg(QDir::toNativeSeparators(it.key()), it.value()));
        }
    }
    publish();
}

void Monitor::stop() {
    timer_->stop();
    const bool wasActive = watcher_->active();
    watcher_->stop();
    batcher_.clear();
    if (scanner_ && scanning_) scanner_->cancel();   // the batch ends as "cancelled"; what was analysed is kept
    if (wasActive) emit logMessage(QStringLiteral("info"), QStringLiteral("Proteção em tempo real desativada."));
}

void Monitor::onChanges(const QList<Change>& changes) {
    const qint64 now = clock_.elapsed();
    for (const Change& c : changes) batcher_.add(c, now);
}

void Monitor::onOverflow(const QString& root) {
    batcher_.rescan(root, clock_.elapsed());
    record(root, QStringLiteral("overflow"), {}, 0, {}, 0,
           {{"message", QStringLiteral("O sistema perdeu parte das alterações desta pasta; ela será verificada de novo por "
                                       "inteiro (arquivos sem mudança vêm do cache).")}});
}

void Monitor::onFailed(const QString& root, const QString& message) {
    if (watcher_->roots().contains(root)) folderErrors_.insert(root, message);
    record(root, QStringLiteral("error"), {}, 0, {}, 0, {{"message", QStringLiteral("Pasta não observada: %1").arg(message)}});
    emit logMessage(QStringLiteral("warning"),
                    QStringLiteral("Proteção em tempo real: %1: %2").arg(QDir::toNativeSeparators(root), message));
    publish();
}

void Monitor::tick() {
    if (scanning_) return;   // changes keep accumulating; the next batch starts when this one ends
    const int before = batcher_.pending();
    const Batch batch = batcher_.take(clock_.elapsed());
    if (!batch.empty()) startBatch(batch);
    else if (before != batcher_.pending()) publish();
}

void Monitor::ensureScanner() {
    if (scanner_ && scannerWorkers_ == settings_.workers && !configChanged_) return;
    configChanged_ = false;
    if (scanner_) {
        scanner_->disconnect(this);
        scanner_->deleteLater();
    }
    gk::scan::Config c = config_;
    c.workers = settings_.workers;
    scanner_ = new gk::scan::Scanner(c, this);
    scannerWorkers_ = settings_.workers;
    connect(scanner_, &gk::scan::Scanner::fileResult, this, [this](const QJsonObject& r) { results_.append(r); });
    connect(scanner_, &gk::scan::Scanner::finished, this, &Monitor::onBatchFinished);
    connect(scanner_, &gk::scan::Scanner::logMessage, this, &Monitor::logMessage);
}

void Monitor::startBatch(const Batch& batch) {
    ensureScanner();
    current_ = batch;
    results_.clear();
    scanning_ = true;
    publish();
    gk::scan::Request request;
    request.targets = batch.targets();
    request.deep = false;   // light while games run: data files by header, archives not expanded
    request.label = QStringLiteral("Proteção em tempo real");
    request.origin = QStringLiteral("realtime");
    request.useCache = true;
    for (const QString& f : batch.stillWriting) {
        emit logMessage(QStringLiteral("warning"),
                        QStringLiteral("Proteção em tempo real: %1 continuava sendo gravado; analisado mesmo assim.").arg(QDir::toNativeSeparators(f)));
    }
    scanner_->start(request);   // a scan that cannot start reports it through `finished` right away
}

void Monitor::onBatchFinished(const QJsonObject& summary) {
    scanning_ = false;
    ++batches_;
    lastBatchAt_ = nowSeconds();
    const qint64 scanId = summary.value("scan_id").toInteger();
    if (scanId > 0) lastScanId_ = scanId;
    if (summary.value("status").toString() == QLatin1String("failed")) {
        const QString why = summary.value("error").toString();
        const QStringList targets = current_.targets();
        record(targets.value(0), QStringLiteral("error"), {}, 0, {}, scanId,
               {{"message", QStringLiteral("A análise de %1 item(ns) falhou: %2").arg(targets.size()).arg(why)}});
        emit logMessage(QStringLiteral("error"), QStringLiteral("Proteção em tempo real: a análise falhou: %1").arg(why));
    } else {
        QHash<QString, Top> tops;
        QStringList order;
        for (const QJsonObject& r : std::as_const(results_)) {
            const QString container = r.value("container").toString();
            const QString path = container.isEmpty() ? r.value("path").toString() : container;
            if (!tops.contains(path)) order << path;
            Top& t = tops[path];
            t.path = path;
            if (container.isEmpty()) {
                t.self = r;
                ++filesScanned_;
            }
            const int risk = riskOf(r.value("risk"));
            if (t.worst.isEmpty() || risk > t.risk) {
                t.risk = risk;
                t.worst = r;
            }
            if (!t.confirmed && riskOf(r.value("risk")) >= 4 && r.value("classification").toString() == QLatin1String("malware"))
                t.confirmed = confirmed(r);
        }
        for (const QString& path : std::as_const(order)) handle(tops[path], scanId);
    }
    results_.clear();
    current_ = {};
    emit batchFinished(summary);
    publish();
}

void Monitor::handle(const Top& top, qint64 scanId) {
    // Below the notification level the finding stays in the batch's scan record only — unless it is a threat
    // confirmed by a signature and the user turned automatic quarantine on: the notification level must not
    // decide whether a confirmed threat is isolated (an EICAR or a known trojan is HIGH, not CRITICAL).
    const bool autoQuarantineApplies = settings_.autoQuarantine && top.confirmed;
    if (top.risk < settings_.notifyMinRisk && !autoQuarantineApplies) return;
    const QJsonObject& w = top.worst;
    const QString sha = top.self.value("sha256").toString();
    const QString classification = w.value("classification").toString();
    const QString detection = detectionOf(w);
    QJsonObject det{{"path", top.path},
                    {"risk", top.risk},
                    {"risk_level", riskName(top.risk)},
                    {"classification", classification},
                    {"detection", detection},
                    {"category", w.value("primary_category")},
                    {"sha256", sha},
                    {"scan_id", scanId}};
    if (!w.value("container").toString().isEmpty()) det.insert(QStringLiteral("member"), w.value("member_path"));
    ++detections_;
    QString action = QStringLiteral("notified");
    QString message;
    QString quarantineId;
    if (autoQuarantineApplies) {
        if (restoredBefore(sha)) {
            action = QStringLiteral("restored_before");
            message = QStringLiteral("Você já restaurou este arquivo da quarentena; ele não foi isolado de novo.");
        } else {
            try {
                gk::db::Database* db = database();
                if (!db) throw std::runtime_error("banco de dados indisponível");
                const auto vault = gk::quarantine::Vault::open(native(quarantineDir_));
                gk::quarantine::Manager manager(*vault, *db);
                gk::quarantine::Request q;
                q.file = native(top.path);
                if (!sha.isEmpty()) q.expected_sha256 = sha.toStdString();   // refuses a file that changed since
                q.reason = "proteção em tempo real (quarentena automática)";
                q.classification = classification.toStdString();
                q.detection = detection.toStdString();
                q.risk = static_cast<gk::Risk>(top.risk);
                if (scanId > 0) q.scan_id = scanId;
                quarantineId = QString::fromStdString(manager.quarantine(q).id);
                action = QStringLiteral("quarantined");
                message = QStringLiteral("Ameaça confirmada por assinatura: arquivo movido para a quarentena automaticamente.");
                ++quarantined_;
            } catch (const std::exception& e) {
                action = QStringLiteral("quarantine_failed");
                message = QStringLiteral("Não foi possível colocar em quarentena: %1. Decida o que fazer na página Análise forense.")
                              .arg(QString::fromUtf8(e.what()));
            }
        }
    } else if (settings_.autoQuarantine) {
        message = QStringLiteral("Não confirmado por assinatura: nada foi movido. Decida o que fazer na página Análise forense.");
    } else {
        message = QStringLiteral("Nada foi movido. Decida o que fazer na página Análise forense.");
    }
    det.insert(QStringLiteral("action"), action);
    det.insert(QStringLiteral("message"), message);
    if (!quarantineId.isEmpty()) det.insert(QStringLiteral("quarantine_id"), quarantineId);
    record(top.path, QStringLiteral("detected"), sha, top.risk, classification, scanId, det);
    if (action == QLatin1String("quarantined") || action == QLatin1String("quarantine_failed")) {
        QJsonObject detail{{"message", message}, {"detection", detection}};
        if (!quarantineId.isEmpty()) detail.insert(QStringLiteral("quarantine_id"), quarantineId);
        record(top.path, action, sha, top.risk, classification, scanId, detail);
    }
    if (action != QLatin1String("restored_before")) emit detected(det);
}

bool Monitor::restoredBefore(const QString& sha256) {
    if (sha256.isEmpty()) return false;
    gk::db::Database* db = database();
    if (!db) return false;
    try {
        const auto restored = db->list_quarantine("restored");
        return std::any_of(restored.begin(), restored.end(), [&](const gk::db::QuarantineRecord& r) {
            return QString::fromStdString(r.sha256).compare(sha256, Qt::CaseInsensitive) == 0;
        });
    } catch (const std::exception&) {
        return false;
    }
}

gk::db::Database* Monitor::database() {
    if (!db_) {
        try {
            db_ = gk::db::Database::open(native(config_.databaseFile()));
        } catch (const std::exception& e) {
            emit logMessage(QStringLiteral("error"), QStringLiteral("Proteção em tempo real: banco de dados indisponível: %1")
                                                         .arg(QString::fromUtf8(e.what())));
        }
    }
    return db_.get();
}

void Monitor::record(const QString& path, const QString& event, const QString& sha256, int risk,
                     const QString& classification, qint64 scanId, const QJsonObject& detail) {
    gk::db::RealtimeEvent e;
    e.at = nowSeconds();
    e.path = path.toStdString();
    e.event = event.toStdString();
    if (!sha256.isEmpty()) e.sha256 = sha256.toStdString();
    e.risk = risk;
    e.classification = classification.toStdString();
    if (scanId > 0) e.scan_id = scanId;
    e.detail = QJsonDocument(detail).toJson(QJsonDocument::Compact).toStdString();
    QJsonObject row{{"at", e.at},
                    {"path", path},
                    {"event", event},
                    {"sha256", sha256.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(sha256)},
                    {"risk", risk},
                    {"risk_level", riskName(risk)},
                    {"classification", classification.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(classification)},
                    {"scan_id", scanId > 0 ? QJsonValue(scanId) : QJsonValue(QJsonValue::Null)},
                    {"detail", detail}};
    try {
        if (gk::db::Database* db = database()) {
            db->add_realtime_event(e);
        } else {
            row.insert(QStringLiteral("not_saved"), true);
        }
    } catch (const std::exception& ex) {
        row.insert(QStringLiteral("not_saved"), true);
        emit logMessage(QStringLiteral("error"), QStringLiteral("Proteção em tempo real: evento não registrado: %1")
                                                     .arg(QString::fromUtf8(ex.what())));
    }
    emit eventRecorded(row);
}

QJsonObject Monitor::status() const {
    const QStringList roots = watcher_->roots();
    QJsonArray folders;
    for (const QString& f : settings_.folders) {
        const QString clean = DirectoryWatcher::cleanFolder(f);
        QString error = folderErrors_.value(clean);
        bool watching = false;
        if (error.isEmpty()) {
            for (const QString& r : roots) {
                const QString prefix = r.endsWith(QLatin1Char('/')) ? r : r + QLatin1Char('/');
#ifdef _WIN32
                const Qt::CaseSensitivity cs = Qt::CaseInsensitive;
#else
                const Qt::CaseSensitivity cs = Qt::CaseSensitive;
#endif
                if (clean.compare(r, cs) == 0 || clean.startsWith(prefix, cs)) watching = true;
            }
            if (!watching && settings_.enabled) error = QStringLiteral("não observada");
        }
        folders.append(QJsonObject{{"path", clean}, {"watching", watching}, {"error", error}});
    }
    return {{"enabled", settings_.enabled},
            {"active", watcher_->active()},
            {"supported", DirectoryWatcher::supported()},
            {"folders", folders},
            {"pending", batcher_.pending()},
            {"scanning", scanning_},
            {"batches", batches_},
            {"files_scanned", filesScanned_},
            {"detections", detections_},
            {"quarantined", quarantined_},
            {"last_scan_id", lastScanId_ > 0 ? QJsonValue(lastScanId_) : QJsonValue(QJsonValue::Null)},
            {"last_batch_at", lastBatchAt_ > 0 ? QJsonValue(lastBatchAt_) : QJsonValue(QJsonValue::Null)},
            {"collapses", batcher_.collapses()},
            {"notify_min_risk", riskName(settings_.notifyMinRisk)},
            {"auto_quarantine", settings_.autoQuarantine}};
}

void Monitor::publish() { emit statusChanged(status()); }

}  // namespace gk::realtime
