// Shared state of the desktop application: data locations (same rules as gamekernel/app_paths.py),
// the shared settings.json, the helper process client and factories for B's native services.
#pragma once

#include "gk/bridge/services.hpp"
#include "gk/ipc/helper_client.hpp"
#include "gk/updates/installer.hpp"

#include <QJsonObject>
#include <QObject>
#include <QString>

#include <functional>
#include <memory>

class QWidget;

namespace gk::app {

class AppContext : public QObject {
    Q_OBJECT
public:
    enum class Level { Info, Success, Warning, Error };
    Q_ENUM(Level)

    using ConfirmFn = std::function<bool(QWidget* parent, const QString& title, const QString& text)>;

    AppContext(QString dataDir, QString resourceDir, gk::ipc::HelperConfig helperConfig, QObject* parent = nullptr);

    // GAMEKERNEL_DATA_DIR → <app>/data when <app>/portable.flag exists → %LOCALAPPDATA%\GameKernel (Windows)
    // → $XDG_DATA_HOME/game-kernel or ~/.local/share/game-kernel.
    static QString defaultDataDir(const QString& appDir);
    static QString appVersion() { return QStringLiteral(GK_APP_VERSION); }   // project() version in CMakeLists.txt
    static QString productName() { return QStringLiteral("Game Kernel"); }   // P1: name still to be confirmed

    QString dataDir() const { return dataDir_; }
    QString resourceDir() const { return resourceDir_; }
    QString signaturesRoot() const;           // <data>/signatures (active/, previous/, staging/)
    QString userKeysDir() const;              // <data>/trusted_keys
    QString builtinKeysDir() const;           // <resources>/signatures/keys
    QStringList trustedKeyDirs() const { return {builtinKeysDir(), userKeysDir()}; }

    // settings.json (contract: gamekernel/config.py). Reads always come from disk; writes are atomic and keep
    // every other key untouched. Values are validated again by Python and C++ readers.
    QJsonObject settings() const;
    QJsonValue setting(const QString& dotted, const QJsonValue& fallback = {}) const;
    bool setSetting(const QString& dotted, const QJsonValue& value, QString* error = nullptr);

    gk::ipc::HelperClient* helper() const { return helper_; }

    // Core services (cpp/bridge), created on first use. The installation is found from the executable's folder
    // (resources, gk-scanworker); the data folder is this context's.
    gk::bridge::Environment coreEnvironment() const;
    gk::bridge::ScanService* scans();
    gk::bridge::HistoryService* history();
    gk::bridge::QuarantineService* quarantine();
    gk::bridge::IntegrityService* integrity();
    gk::bridge::RealtimeService* realtime();
    gk::bridge::PerformanceService* performance();
    gk::bridge::OptimizerService* optimizer();
    const gk::bridge::Catalog& catalog();
    // realtime.* and scan.excluded_paths from settings.json, with the ranges of gamekernel/config.py.
    gk::realtime::Settings realtimeSettings() const;
    // Starts real-time protection when settings.json has it on (called once at start-up); afterwards every
    // change to realtime.* or scan.excluded_paths is applied by itself.
    void startRealtimeIfEnabled();
    std::unique_ptr<gk::updates::Installer> makeInstaller() const;

    // Every destructive or security-relevant action asks through this (tests replace it).
    ConfirmFn confirm;
    bool ask(QWidget* parent, const QString& title, const QString& text) const;

signals:
    void notify(gk::app::AppContext::Level level, const QString& title, const QString& text);
    // After a successful setSetting(): pages showing the same option refresh themselves.
    void settingChanged(const QString& dotted);

private:
    QString dataDir_;
    QString resourceDir_;
    gk::bridge::ScanService* scans_ = nullptr;
    gk::bridge::HistoryService* history_ = nullptr;
    gk::bridge::QuarantineService* quarantine_ = nullptr;
    gk::bridge::IntegrityService* integrity_ = nullptr;
    gk::bridge::RealtimeService* realtime_ = nullptr;
    gk::bridge::PerformanceService* performance_ = nullptr;
    gk::bridge::OptimizerService* optimizer_ = nullptr;
    std::unique_ptr<gk::bridge::Catalog> catalog_;
    gk::ipc::HelperClient* helper_;
};

}  // namespace gk::app
