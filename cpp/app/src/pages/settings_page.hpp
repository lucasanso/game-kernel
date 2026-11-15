// Settings page. Only options that something reads today are shown (no inert switches): scanning (read by the
// core through gk::scan::Config::load — the application, real-time protection and gk-cli), report privacy
// defaults (helper reports.generate and the reports page), the staleness warning of the offline update center,
// behavioural analysis (helper sandbox.* and its page) and where the data lives. Values are validated with the
// same ranges as gamekernel/config.py and written atomically to settings.json, keeping every other key.
// Real-time options live on their own page.
#pragma once

#include "../app_context.hpp"

#include <QWidget>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class QSpinBox;

namespace gk::app {

class SettingsPage : public QWidget {
    Q_OBJECT
public:
    explicit SettingsPage(AppContext* ctx, QWidget* parent = nullptr);

    // Each setter validates, writes settings.json and returns false (with lastError()) when refused.
    bool setDefaultMode(const QString& mode);      // deep | quick
    bool setScanWorkers(int workers);              // 1..32
    bool setMaxFileSizeMb(int mb);                 // 8..16384
    bool setArchiveDepth(int depth);               // 0..10
    bool setArchiveTotalMb(int mb);                // 16..65536
    bool setClamavEnabled(bool on);
    bool addExcludedFolder(const QString& folder); // existing folder
    bool removeExcludedFolder(const QString& folder);
    bool setExcludedExtensions(const QString& text);   // ".pak, bk2 ; .ogg" -> [".bk2", ".ogg", ".pak"]
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
    QComboBox* mode_;
    QSpinBox* workers_;
    QSpinBox* maxFileMb_;
    QSpinBox* archiveDepth_;
    QSpinBox* archiveTotalMb_;
    QCheckBox* clamav_;
    QListWidget* excludedFolders_;
    QPushButton* removeExcluded_;
    QLineEdit* excludedExt_;
    QCheckBox* redact_;
    QCheckBox* hostname_;
    QSpinBox* staleDays_;
    QCheckBox* sandboxEnabled_;
    QSpinBox* sandboxTimeout_;
    QLabel* sysmonLabel_;
    QPushButton* sysmonClear_;
};

}  // namespace gk::app
