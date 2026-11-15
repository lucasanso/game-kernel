// "Quarentena": files moved into the encrypted vault (gk::bridge::QuarantineService). Restoring checks the
// content against the SHA-256 recorded when it was quarantined; deleting is permanent and asks first;
// "Verificar cofre" authenticates every item. Nothing happens without the user's action.
#pragma once

#include "../app_context.hpp"

#include <QJsonArray>
#include <QWidget>

class QCheckBox;
class QLabel;
class QPushButton;
class QTableWidget;

namespace gk::app {

class QuarantinePage : public QWidget {
    Q_OBJECT
public:
    explicit QuarantinePage(AppContext* ctx, QWidget* parent = nullptr);
    void refresh();
    int itemCount() const;
    bool selectItem(const QString& id);
    QString selectedId() const;
    bool restoreSelected(const QString& destination = {});   // empty = original location; asks first
    bool eraseSelected();                                    // asks first
    void verifyVault();
    void setShowFinished(bool on);

signals:
    void listed(int count);
    void operationFinished(const QString& kind, bool ok, const QString& message);

private:
    void onFinished(qint64 request, const QString& kind, bool ok, const QJsonObject& result, const QString& message);
    void updateButtons();

    AppContext* ctx_;
    qint64 listRequest_ = -1;
    qint64 opRequest_ = -1;
    QString pendingRestoreId_, pendingRestoreTo_;
    QJsonArray items_;
    QCheckBox* showFinished_;
    QTableWidget* table_;
    QLabel* empty_;
    QLabel* status_;
    QPushButton* restore_;
    QPushButton* restoreTo_;
    QPushButton* erase_;
    QPushButton* verify_;
};

}  // namespace gk::app
