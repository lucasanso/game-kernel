#include "history_page.hpp"

#include "../ui_kit.hpp"
#include "scan_table.hpp"

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>

namespace gk::app {

HistoryPage::HistoryPage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);
    auto* card = new Card(QStringLiteral("Varreduras deste computador"), content);
    auto* header = new QHBoxLayout;
    header->addWidget(mutedLabel(QStringLiteral("Todas as varreduras ficam registradas no banco local, com os resultados de cada "
                                                "arquivo. Nada sai deste computador."),
                                 card),
                      1);
    auto* refreshButton = new QPushButton(icon(QStringLiteral("refresh")), QStringLiteral("Atualizar"), card);
    header->addWidget(refreshButton, 0, Qt::AlignTop);
    card->body()->addLayout(header);
    table_ = makeScanTable(card);
    card->body()->addWidget(table_);
    empty_ = mutedLabel(QString(), card);
    empty_->setVisible(false);
    card->body()->addWidget(empty_);
    auto* actions = new QHBoxLayout;
    actions->addStretch();
    report_ = new QPushButton(icon(QStringLiteral("file-text")), QStringLiteral("Gerar relatório"), card);
    open_ = new QPushButton(icon(QStringLiteral("shield-check"), Qt::white), QStringLiteral("Abrir a análise"), card);
    open_->setProperty("primary", true);
    actions->addWidget(report_);
    actions->addWidget(open_);
    card->body()->addLayout(actions);
    col->addWidget(card);
    col->addStretch();

    connect(ctx_->history(), &gk::bridge::HistoryService::scansListed, this, [this](qint64 request, const QJsonArray& scans) {
        if (request != request_) return;
        request_ = -1;
        fillScanTable(table_, scans);
        const bool none = scans.isEmpty();
        table_->setVisible(!none);
        empty_->setVisible(none);
        empty_->setText(QStringLiteral("Nenhuma varredura registrada ainda. Faça a primeira em Segurança do jogo."));
        updateButtons();
        emit loaded(table_->rowCount());
    });
    connect(ctx_->history(), &gk::bridge::HistoryService::failed, this, [this](qint64 request, const QString& message) {
        if (request != request_) return;
        request_ = -1;
        table_->setVisible(false);
        empty_->setVisible(true);
        empty_->setText(QStringLiteral("Não foi possível ler o histórico: %1").arg(message));
        updateButtons();
        emit loaded(0);
    });
    connect(refreshButton, &QPushButton::clicked, this, &HistoryPage::refresh);
    connect(table_, &QTableWidget::itemSelectionChanged, this, &HistoryPage::updateButtons);
    connect(table_, &QTableWidget::cellDoubleClicked, this, [this] {
        if (selectedScan() > 0) emit openResults(selectedScan());
    });
    connect(open_, &QPushButton::clicked, this, [this] {
        if (selectedScan() > 0) emit openResults(selectedScan());
    });
    connect(report_, &QPushButton::clicked, this, [this] {
        if (selectedScan() > 0) emit openReports(selectedScan());
    });
    updateButtons();
    refresh();
}

void HistoryPage::refresh() {
    if (request_ < 0) request_ = ctx_->history()->listScans(500);
}

int HistoryPage::scanCount() const { return table_->rowCount(); }
qint64 HistoryPage::selectedScan() const { return selectedScanId(table_); }
bool HistoryPage::selectScan(qint64 scanId) { return selectScanId(table_, scanId); }
QString HistoryPage::emptyStateText() const { return empty_->isVisibleTo(this) ? empty_->text() : QString(); }

void HistoryPage::updateButtons() {
    const bool any = selectedScan() > 0;
    open_->setEnabled(any);
    report_->setEnabled(any);
}

}  // namespace gk::app
