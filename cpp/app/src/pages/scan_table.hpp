// Table of recorded scans shared by the History and Reports pages. Accepts the rows of the core service
// (gk::bridge::HistoryService: epoch times, integer max_risk + max_risk_level) and of the helper's
// reports.scans (ISO times, max_risk {level,label}).
#pragma once

#include <QJsonArray>
#include <QString>

class QTableWidget;
class QWidget;

namespace gk::app {

QTableWidget* makeScanTable(QWidget* parent);
void fillScanTable(QTableWidget* table, const QJsonArray& scans);   // keeps the previous selection when possible
qint64 selectedScanId(const QTableWidget* table);                  // -1 when nothing is selected
bool selectScanId(QTableWidget* table, qint64 scanId);

// Shared wording.
QString scanModeLabel(const QString& mode);
QString scanStatusLabel(const QString& status);
QString scanWhen(const QJsonValue& time);                          // ISO text or epoch seconds -> dd/MM/yyyy HH:mm

}  // namespace gk::app
