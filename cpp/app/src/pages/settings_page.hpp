// Settings page. Only options that something reads today are shown (no inert switches): report privacy
// defaults (helper reports.generate and the reports page), the staleness warning of the offline update center,
// behavioural analysis (helper sandbox.* and its page) and where the data lives. Values are validated with the
// same ranges as gamekernel/config.py and written atomically to settings.json, keeping every other key.
// Scan, engine, real-time, quarantine and interface options join this page when their C++ consumers exist
// (cpp/bridge, Agent A).
#pragma once

#include "../app_context.hpp"

#include <QWidget>

class QCheckBox;
class QLabel;
class QPushButton;
class QSpinBox;

namespace gk::app {

class SettingsPage : public QWidget {
    Q_OBJECT
public:
    explicit SettingsPage(AppContext* ctx, QWidget* parent = nullptr);

    // Each setter validates, writes settings.json and returns false (with lastError()) when refused.
    bool setRedactUsername(bool on);
    bool setIncludeHostname(bool on);
    bool setStaleAfterDays(int days);              // 1..365
    bool setSandboxEnabled(bool on);
    bool setSandboxTimeout(int seconds);           // 30..1800
    bool setSysmonPath(const QString& path);       // empty clears; else an existing Sysmon64.exe / Sysmon.exe
    bool restoreDefaults();                        // asks for confirmation
    QString lastError() const { return error_; }
    void reload();                                 // widgets from settings.json

private:
    bool write(const QString& key, const QJsonValue& value);

    AppContext* ctx_;
    QString error_;
    QCheckBox* redact_;
    QCheckBox* hostname_;
    QSpinBox* staleDays_;
    QCheckBox* sandboxEnabled_;
    QSpinBox* sandboxTimeout_;
    QLabel* sysmonLabel_;
    QPushButton* sysmonClear_;
};

}  // namespace gk::app
