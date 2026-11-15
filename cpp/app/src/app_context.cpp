#include "app_context.hpp"

#include <algorithm>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QMessageBox>
#include <QPushButton>
#include <QSaveFile>
#include <QStandardPaths>

namespace gk::app {

AppContext::AppContext(QString dataDir, QString resourceDir, gk::ipc::HelperConfig helperConfig, QObject* parent)
    : QObject(parent), dataDir_(std::move(dataDir)), resourceDir_(std::move(resourceDir)),
      helper_(new gk::ipc::HelperClient(std::move(helperConfig), this)) {
    QDir().mkpath(dataDir_);
    confirm = [](QWidget* owner, const QString& title, const QString& text) {
        QMessageBox box(QMessageBox::Question, title, text, QMessageBox::NoButton, owner);
        auto* yes = box.addButton(QStringLiteral("Confirmar"), QMessageBox::AcceptRole);
        box.addButton(QStringLiteral("Cancelar"), QMessageBox::RejectRole);
        box.exec();
        return box.clickedButton() == yes;
    };
}

QString AppContext::defaultDataDir(const QString& appDir) {
    const QString override = qEnvironmentVariable("GAMEKERNEL_DATA_DIR");
    if (!override.isEmpty()) return QDir(override).absolutePath();
    if (QFileInfo::exists(QDir(appDir).filePath(QStringLiteral("portable.flag"))))
        return QDir(appDir).filePath(QStringLiteral("data"));
#if defined(Q_OS_WIN)
    QString local = qEnvironmentVariable("LOCALAPPDATA");
    if (local.isEmpty()) local = QDir::home().filePath(QStringLiteral("AppData/Local"));
    return QDir(local).filePath(QStringLiteral("GameKernel"));
#else
    QString xdg = qEnvironmentVariable("XDG_DATA_HOME");
    if (xdg.isEmpty()) xdg = QDir::home().filePath(QStringLiteral(".local/share"));
    return QDir(xdg).filePath(QStringLiteral("game-kernel"));
#endif
}

QString AppContext::signaturesRoot() const { return QDir(dataDir_).filePath(QStringLiteral("signatures")); }
QString AppContext::userKeysDir() const { return QDir(dataDir_).filePath(QStringLiteral("trusted_keys")); }
QString AppContext::builtinKeysDir() const { return QDir(resourceDir_).filePath(QStringLiteral("signatures/keys")); }

QJsonObject AppContext::settings() const {
    QFile f(QDir(dataDir_).filePath(QStringLiteral("settings.json")));
    if (!f.open(QIODevice::ReadOnly) || f.size() > 4 * 1024 * 1024) return {};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    return doc.isObject() ? doc.object() : QJsonObject{};
}

QJsonValue AppContext::setting(const QString& dotted, const QJsonValue& fallback) const {
    QJsonValue node = settings();
    for (const QString& part : dotted.split('.')) {
        if (!node.isObject() || !node.toObject().contains(part)) return fallback;
        node = node.toObject().value(part);
    }
    return node;
}

namespace {
QJsonObject withValue(QJsonObject obj, QStringList parts, const QJsonValue& value) {
    const QString key = parts.takeFirst();
    if (parts.isEmpty()) obj.insert(key, value);
    else obj.insert(key, withValue(obj.value(key).toObject(), parts, value));
    return obj;
}
}  // namespace

bool AppContext::setSetting(const QString& dotted, const QJsonValue& value, QString* error) {
    const QJsonObject updated = withValue(settings(), dotted.split('.'), value);
    QSaveFile f(QDir(dataDir_).filePath(QStringLiteral("settings.json")));
    if (!f.open(QIODevice::WriteOnly) || f.write(QJsonDocument(updated).toJson(QJsonDocument::Indented)) < 0 ||
        !f.commit()) {
        if (error) *error = f.errorString();
        return false;
    }
    emit settingChanged(dotted);
    return true;
}

std::unique_ptr<gk::updates::Installer> AppContext::makeInstaller() const {
    QStringList problems;
    auto keys = gk::updates::loadTrustedKeys(trustedKeyDirs(), &problems);
    return std::make_unique<gk::updates::Installer>(signaturesRoot(), std::move(keys), appVersion());
}

gk::bridge::Environment AppContext::coreEnvironment() const {
    return {QCoreApplication::applicationDirPath(), dataDir_};
}

gk::bridge::ScanService* AppContext::scans() {
    if (!scans_) scans_ = new gk::bridge::ScanService(coreEnvironment(), this);
    return scans_;
}

gk::bridge::HistoryService* AppContext::history() {
    if (!history_) history_ = new gk::bridge::HistoryService(coreEnvironment(), this);
    return history_;
}

gk::bridge::QuarantineService* AppContext::quarantine() {
    if (!quarantine_) quarantine_ = new gk::bridge::QuarantineService(coreEnvironment(), this);
    return quarantine_;
}

gk::bridge::IntegrityService* AppContext::integrity() {
    if (!integrity_) integrity_ = new gk::bridge::IntegrityService(coreEnvironment(), this);
    return integrity_;
}

gk::bridge::RealtimeService* AppContext::realtime() {
    if (!realtime_) {
        realtime_ = new gk::bridge::RealtimeService(coreEnvironment(), this);
        connect(this, &AppContext::settingChanged, realtime_, [this](const QString& key) {
            if (key.startsWith(QLatin1String("realtime.")) || key == QLatin1String("scan.excluded_paths"))
                realtime_->apply(realtimeSettings());
        });
    }
    return realtime_;
}

gk::bridge::PerformanceService* AppContext::performance() {
    if (!performance_) performance_ = new gk::bridge::PerformanceService(this);
    return performance_;
}

gk::bridge::OptimizerService* AppContext::optimizer() {
    if (!optimizer_) optimizer_ = new gk::bridge::OptimizerService(coreEnvironment(), this);
    return optimizer_;
}

gk::realtime::Settings AppContext::realtimeSettings() const {
    const QJsonObject r = setting(QStringLiteral("realtime")).toObject();
    auto clamp = [](const QJsonValue& v, int lo, int hi, int fallback) {
        return v.isDouble() ? std::clamp(v.toInt(fallback), lo, hi) : fallback;
    };
    gk::realtime::Settings s;
    s.enabled = r.value("enabled").toBool(false);
    for (const auto& f : r.value("folders").toArray())
        if (!f.toString().trimmed().isEmpty()) s.folders << f.toString();
    static const QStringList levels{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    const int level = levels.indexOf(r.value("notify_min_risk").toString());
    s.notifyMinRisk = level < 0 ? 3 : level + 1;
    s.autoQuarantine = r.value("auto_quarantine").toBool(false);
    s.batchSeconds = clamp(r.value("batch_seconds"), 2, 300, 8);
    s.stableSeconds = clamp(r.value("stable_seconds"), 1, 60, 2);
    s.workers = clamp(r.value("max_workers"), 1, 8, 1);
    for (const auto& p : setting(QStringLiteral("scan.excluded_paths")).toArray())
        if (!p.toString().trimmed().isEmpty()) s.excludedPaths << p.toString();
    return s;
}

void AppContext::startRealtimeIfEnabled() {
    const gk::realtime::Settings s = realtimeSettings();
    if (s.enabled) realtime()->apply(s);
}

const gk::bridge::Catalog& AppContext::catalog() {
    if (!catalog_) catalog_ = std::make_unique<gk::bridge::Catalog>(coreEnvironment());
    return *catalog_;
}

bool AppContext::ask(QWidget* parent, const QString& title, const QString& text) const {
    return confirm ? confirm(parent, title, text) : false;
}

}  // namespace gk::app
