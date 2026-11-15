// Forensic reports page (helper methods reports.scans, reports.formats and reports.generate).
// Lists the scans recorded in the local database (today written by gk-cli; later by the scan pages),
// generates JSON/HTML/PDF reports with the privacy options and lists the reports already in <data>/reports.
// The database is only read (PRAGMA query_only in the helper) and never created by this page.
#pragma once

#include "../app_context.hpp"

#include <QJsonArray>
#include <QJsonObject>
#include <QWidget>

class QCheckBox;
class QLabel;
class QProgressBar;
class QPushButton;
class QTableWidget;

namespace gk::app {

class StatusPill;

class ReportsPage : public QWidget {
    Q_OBJECT
public:
    explicit ReportsPage(AppContext* ctx, QWidget* parent = nullptr);

    void refresh();                              // formats, scans and generated files
    bool selectScan(qint64 scanId);              // false when the scan is not listed
    void focusScan(qint64 scanId);               // select now, or as soon as the list (re)loads
    qint64 selectedScan() const;                 // -1 when nothing is selected
    bool generate();                             // false (and nothing sent) without a scan or a format
    int scanCount() const;
    QStringList generatedFiles() const;          // file names in <data>/reports, newest first
    QString emptyStateText() const;              // shown instead of the table when nothing was scanned
    QString reportsDir() const;

signals:
    void scansLoaded(int count);
    void reportFinished(bool ok, const QString& message);

private:
    void onSucceeded(qint64 id, const QJsonValue& result);
    void onFailed(qint64 id, const gk::ipc::CallError& error);
    void onEvent(qint64 id, const QString& name, const QJsonObject& payload);
    void showScans(const QJsonArray& scans, bool databasePresent);
    void listGeneratedFiles();
    void updateButtons();

    AppContext* ctx_;
    qint64 scansCall_ = -1;
    qint64 formatsCall_ = -1;
    qint64 generateCall_ = -1;
    QString lastReport_;
    qint64 pendingFocus_ = -1;
    QTableWidget* scans_;
    QLabel* empty_;
    QCheckBox* html_;
    QCheckBox* json_;
    QCheckBox* pdf_;
    QCheckBox* includeClean_;
    QCheckBox* keepUsername_;
    QCheckBox* includeHostname_;
    QPushButton* generateButton_;
    QPushButton* openReport_;
    QProgressBar* progress_;
    QLabel* status_;
    QTableWidget* files_;
};

}  // namespace gk::app
