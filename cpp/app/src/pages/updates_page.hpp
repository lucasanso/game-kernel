// Offline Update Center: shows the active signature set, verifies and installs .gkpkg packages
// (cpp/updates), rolls back, and manages trusted publisher keys. All heavy work runs on a
// worker thread; the UI never blocks.
#pragma once

#include "../app_context.hpp"

#include <QJsonObject>
#include <QWidget>

class QLabel;
class QPushButton;
class QTableWidget;

namespace gk::app {

class StatusPill;

class UpdatesPage : public QWidget {
    Q_OBJECT
public:
    explicit UpdatesPage(AppContext* ctx, QWidget* parent = nullptr);

    void refresh();
    void importPackage(const QString& packagePath);   // async → operationFinished
    void rollbackToPrevious();                        // async → operationFinished
    bool addTrustedKey(const QString& pubPath);       // asks for confirmation (shows the key id)
    bool removeTrustedKey(const QString& keyId);      // user keys only; asks for confirmation
    bool busy() const { return busy_; }
    QString activeVersion() const;
    bool stale() const { return stale_; }

    static QString describeError(const QString& code);

signals:
    void operationFinished(bool ok, const QString& code, const QString& message);

private:
    void chooseAndImport();
    void chooseAndAddKey();
    void installVerified(const QString& packagePath, bool allowDowngrade);
    void finishOperation(bool ok, const QString& code, const QString& message, const QStringList& details = {});
    void setBusy(bool busy, const QString& what = {});
    void fillKeys();

    AppContext* ctx_;
    bool busy_ = false;
    bool stale_ = false;
    QJsonObject active_;
    StatusPill* statePill_;
    QLabel* summary_;
    QLabel* operation_;
    QTableWidget* components_;
    QTableWidget* keys_;
    QTableWidget* history_;
    QPushButton* importButton_;
    QPushButton* rollbackButton_;
    QPushButton* removeKeyButton_;
};

}  // namespace gk::app
