// "Proteção em tempo real": the folders watched by gk::bridge::RealtimeService, how it acts on a finding, and
// the log of what it found (realtime_events). Every option is a realtime.* key of settings.json — the same
// keys gamekernel/config.py validates — and takes effect at once. The page says plainly what the protection
// does not do: it does not stop a program from starting before the analysis, and it runs only while the
// application is open (in the notification area when the window is closed).
#pragma once

#include "../app_context.hpp"

#include <QJsonArray>
#include <QWidget>

class QCheckBox;
class QComboBox;
class QLabel;
class QListWidget;
class QPushButton;
class QSpinBox;
class QTableWidget;

namespace gk::app {

class StatusPill;

class RealtimePage : public QWidget {
    Q_OBJECT
public:
    explicit RealtimePage(AppContext* ctx, QWidget* parent = nullptr);

    bool setProtectionEnabled(bool on);          // refuses to turn on without a folder
    bool addFolder(const QString& folder);       // existing folder, outside the program's data folder
    bool removeFolder(const QString& folder);
    bool setNotifyMinRisk(const QString& level); // INFO | LOW | MEDIUM | HIGH | CRITICAL
    bool setAutoQuarantine(bool on);             // turning it on asks first
    bool setBatchSeconds(int seconds);           // 2..300
    bool setStableSeconds(int seconds);          // 1..60
    void refreshEvents();
    void reload();                               // settings.json -> controls

    [[nodiscard]] QString statusText() const;    // pill — details
    [[nodiscard]] QStringList folders() const;
    [[nodiscard]] QString folderState(int row) const;
    [[nodiscard]] int eventCount() const;
    [[nodiscard]] QString lastError() const { return error_; }
    bool openSelectedEvent();                    // opens the analysis of the selected event's batch

signals:
    void statusShown(const QJsonObject& status);
    void eventsLoaded(int count);
    void openResults(qint64 scanId);

private:
    bool write(const QString& key, const QJsonValue& value);
    void showStatus(const QJsonObject& status);
    void showEvents(const QJsonArray& events);

    AppContext* ctx_;
    QString error_;
    qint64 eventsRequest_ = -1;
    bool eventsDirty_ = false;
    QJsonArray events_;
    QJsonObject status_;
    StatusPill* pill_;
    QLabel* summary_;
    QPushButton* toggle_;
    QListWidget* folderList_;
    QPushButton* addFolder_;
    QPushButton* removeFolder_;
    QComboBox* notifyLevel_;
    QCheckBox* autoQuarantine_;
    QSpinBox* batch_;
    QSpinBox* stable_;
    QTableWidget* table_;
    QLabel* empty_;
    QPushButton* openScan_;
};

}  // namespace gk::app
