// "Painel": the state of the protection at a glance — last scan, signatures, quarantine and the integrity of
// the installation — with shortcuts. Every tile is computed from the real services; nothing is estimated.
#pragma once

#include "../app_context.hpp"

#include <QWidget>

class QLabel;
class QPushButton;

namespace gk::app {

class StatusPill;

class DashboardPage : public QWidget {
    Q_OBJECT
public:
    explicit DashboardPage(AppContext* ctx, QWidget* parent = nullptr);
    void refresh();
    QString lastScanText() const;
    QString signaturesText() const;
    QString quarantineText() const;
    QString integrityText() const;
    QString integrityStatus() const;   // badge text

signals:
    void refreshed();
    void requestScan(const QString& folder);
    void openResults(qint64 scanId);
    void openUpdates();
    void openQuarantine();
    void openHistory();

private:
    void showSignatures();

    AppContext* ctx_;
    qint64 scansRequest_ = -1;
    qint64 quarantineRequest_ = -1;
    qint64 lastScanId_ = -1;
    int pending_ = 0;
    StatusPill* scanPill_;
    QLabel* scanText_;
    QPushButton* openLast_;
    StatusPill* sigPill_;
    QLabel* sigText_;
    StatusPill* quarantinePill_;
    QLabel* quarantineText_;
    StatusPill* integrityPill_;
    QLabel* integrityText_;
};

}  // namespace gk::app
