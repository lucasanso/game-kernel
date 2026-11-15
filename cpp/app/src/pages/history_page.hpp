// "Histórico": every scan recorded on this computer (gk::bridge::HistoryService), with shortcuts to its
// forensic analysis and to its report.
#pragma once

#include "../app_context.hpp"

#include <QWidget>

class QCheckBox;
class QLabel;
class QPushButton;
class QTableWidget;

namespace gk::app {

class HistoryPage : public QWidget {
    Q_OBJECT
public:
    explicit HistoryPage(AppContext* ctx, QWidget* parent = nullptr);
    void refresh();
    int scanCount() const;
    qint64 selectedScan() const;
    bool selectScan(qint64 scanId);
    QString emptyStateText() const;
    void setIncludeRealtime(bool on);   // the small batches of real-time protection are hidden by default

signals:
    void loaded(int count);
    void openResults(qint64 scanId);
    void openReports(qint64 scanId);

private:
    void updateButtons();

    AppContext* ctx_;
    qint64 request_ = -1;
    QCheckBox* includeRealtime_;
    QTableWidget* table_;
    QLabel* empty_;
    QPushButton* open_;
    QPushButton* report_;
};

}  // namespace gk::app
