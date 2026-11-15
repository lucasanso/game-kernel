// "Análise forense": the results of one scan (gk::bridge::HistoryService) — what was found, where (file,
// archive member, offset or line), why (evidence with source, rule and false-positive note) and what to do
// (recommendations of the risk engine). The user can quarantine a file (confirmation, SHA-256 checked against
// the analysed content) or open its folder.
#pragma once

#include "../app_context.hpp"

#include <QJsonArray>
#include <QJsonObject>
#include <QWidget>

class QComboBox;
class QLabel;
class QPushButton;
class QTableWidget;

namespace gk::app {

class StatusPill;

class ResultsPage : public QWidget {
    Q_OBJECT
public:
    explicit ResultsPage(AppContext* ctx, QWidget* parent = nullptr);

    void loadScan(qint64 scanId);
    void loadLatest();                              // most recent scan, if any
    qint64 scanId() const { return scanId_; }
    int findingsCount() const;                      // visible rows (after the filter)
    void setFilter(const QString& classification);  // "" = all
    bool selectFile(const QString& name);
    QJsonObject selectedResult() const;
    QString detailText() const;                     // plain text of the detail pane (tests, accessibility)
    bool quarantineSelected();                      // asks for confirmation; false when nothing was sent

signals:
    void loaded(int findings);
    void quarantineFinished(bool ok, const QString& message);
    void openReports(qint64 scanId);

private:
    void showScan(const QJsonObject& scan, const QJsonArray& results);
    void applyFilter();
    void showDetail();
    void updateButtons();

    AppContext* ctx_;
    qint64 scanId_ = -1;
    qint64 loadRequest_ = -1;
    qint64 latestRequest_ = -1;
    qint64 quarantineRequest_ = -1;
    QJsonArray results_;
    QJsonObject scan_;
    QLabel* scanLine_;
    QLabel* limitations_;
    QComboBox* filter_;
    QTableWidget* table_;
    QLabel* empty_;
    QLabel* detailTitle_;
    StatusPill* detailRisk_;
    QLabel* detail_;
    QTableWidget* evidences_;
    QPushButton* quarantine_;
    QPushButton* openFolder_;
    QPushButton* report_;
};

}  // namespace gk::app
