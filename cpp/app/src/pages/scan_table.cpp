#include "scan_table.hpp"

#include "../ui_kit.hpp"

#include <QDateTime>
#include <QDir>
#include <QHash>
#include <QHeaderView>
#include <QJsonObject>
#include <QTableWidget>

namespace gk::app {

namespace {

QTableWidgetItem* cell(const QString& text) {
    auto* item = new QTableWidgetItem(text);
    item->setToolTip(text);
    return item;
}

}  // namespace

QString scanModeLabel(const QString& mode) {
    if (mode == QLatin1String("deep")) return QStringLiteral("Completa");
    if (mode == QLatin1String("quick")) return QStringLiteral("Rápida");
    return mode;
}

QString scanStatusLabel(const QString& status) {
    static const QHash<QString, QString> labels{{"completed", "Concluída"}, {"cancelled", "Cancelada"},
                                                {"failed", "Falhou"},       {"running", "Em andamento"},
                                                {"interrupted", "Interrompida"}};
    return labels.value(status, status);
}

QString scanWhen(const QJsonValue& time) {
    QDateTime t;
    if (time.isString()) t = QDateTime::fromString(time.toString(), Qt::ISODate);
    else if (time.isDouble()) t = QDateTime::fromMSecsSinceEpoch(qint64(time.toDouble() * 1000.0));
    return t.isValid() ? t.toLocalTime().toString(QStringLiteral("dd/MM/yyyy HH:mm")) : QStringLiteral("—");
}

QTableWidget* makeScanTable(QWidget* parent) {
    auto* table = makeTable({"Nº", "Início", "Modo", "Alvos", "Arquivos", "Ameaças", "Suspeitos", "Risco máximo", "Situação"},
                            parent);
    // Paths are the long column: they stretch and are elided in the middle; the status fits its text.
    table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    table->horizontalHeader()->setSectionResizeMode(8, QHeaderView::ResizeToContents);
    table->setTextElideMode(Qt::ElideMiddle);
    table->setWordWrap(false);
    table->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    return table;
}

void fillScanTable(QTableWidget* table, const QJsonArray& scans) {
    const qint64 previous = selectedScanId(table);
    table->setRowCount(0);
    for (const auto& v : scans) {
        const QJsonObject s = v.toObject();
        const int row = table->rowCount();
        table->insertRow(row);
        auto* id = cell(QString::number(s.value("scan_id").toInteger()));
        id->setData(Qt::UserRole, s.value("scan_id").toInteger());
        QStringList targets;
        for (const auto& t : s.value("targets").toArray()) targets << QDir::toNativeSeparators(t.toString());
        QString level, label;
        if (s.value("max_risk").isObject()) {                 // helper rows
            level = s.value("max_risk").toObject().value("level").toString();
            label = s.value("max_risk").toObject().value("label").toString();
        } else {                                               // core rows
            level = s.value("max_risk_level").toString();
            label = riskLabel(level);
        }
        auto* riskItem = cell(label);
        riskItem->setForeground(riskColor(level));
        const QStringList texts{scanWhen(s.value("started_at")), scanModeLabel(s.value("mode").toString()),
                                targets.join(QStringLiteral("; ")),
                                QString::number(s.value("files_found").toInteger()),
                                QString::number(s.value("threats").toInteger()),
                                QString::number(s.value("suspicious").toInteger() + s.value("pua").toInteger())};
        table->setItem(row, 0, id);
        for (int c = 0; c < texts.size(); ++c) table->setItem(row, c + 1, cell(texts[c]));
        table->setItem(row, 7, riskItem);
        QString status = scanStatusLabel(s.value("status").toString());
        if (!s.value("error").toString().isEmpty()) status += QStringLiteral(" — ") + s.value("error").toString();
        table->setItem(row, 8, cell(status));
    }
    fitTableToContents(table);
    if (previous < 0 || !selectScanId(table, previous)) {
        if (table->rowCount() > 0) table->selectRow(0);
    }
}

qint64 selectedScanId(const QTableWidget* table) {
    const auto rows = table->selectionModel() ? table->selectionModel()->selectedRows() : QModelIndexList{};
    if (rows.isEmpty()) return -1;
    const QTableWidgetItem* item = table->item(rows.first().row(), 0);
    return item ? item->data(Qt::UserRole).toLongLong() : -1;
}

bool selectScanId(QTableWidget* table, qint64 scanId) {
    for (int row = 0; row < table->rowCount(); ++row) {
        if (table->item(row, 0)->data(Qt::UserRole).toLongLong() == scanId) {
            table->selectRow(row);
            return true;
        }
    }
    return false;
}

}  // namespace gk::app
