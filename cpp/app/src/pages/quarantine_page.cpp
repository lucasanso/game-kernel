#include "quarantine_page.hpp"

#include "../ui_kit.hpp"
#include "scan_table.hpp"

#include <QCheckBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonObject>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>

namespace gk::app {

namespace {

QTableWidgetItem* cell(const QString& text) {
    auto* item = new QTableWidgetItem(text);
    item->setToolTip(text);
    return item;
}

QString statusLabel(const QString& status) {
    if (status == QLatin1String("quarantined")) return QStringLiteral("Em quarentena");
    if (status == QLatin1String("restored")) return QStringLiteral("Restaurado");
    if (status == QLatin1String("deleted")) return QStringLiteral("Apagado");
    return status;
}

}  // namespace

QuarantinePage::QuarantinePage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);
    auto* card = new Card(QStringLiteral("Itens em quarentena"), content);
    card->body()->addWidget(mutedLabel(QStringLiteral("Arquivos movidos para um cofre criptografado neste computador. Eles não "
                                                      "podem ser executados de lá. A restauração confere o conteúdo com o "
                                                      "registrado na entrada; apagar é definitivo."),
                                       card));
    showFinished_ = new QCheckBox(QStringLiteral("Mostrar também os restaurados e apagados"), card);
    card->body()->addWidget(showFinished_);
    table_ = makeTable({"Quando", "Arquivo original", "Risco", "Classificação", "Detecção", "Motivo", "Situação"}, card);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    table_->setTextElideMode(Qt::ElideMiddle);
    table_->setWordWrap(false);
    card->body()->addWidget(table_);
    empty_ = mutedLabel(QStringLiteral("A quarentena está vazia."), card);
    empty_->setVisible(false);
    card->body()->addWidget(empty_);
    auto* actions = new QHBoxLayout;
    verify_ = new QPushButton(icon(QStringLiteral("shield-check")), QStringLiteral("Verificar cofre"), card);
    actions->addWidget(verify_);
    actions->addStretch();
    erase_ = new QPushButton(icon(QStringLiteral("trash"), Qt::white), QStringLiteral("Apagar definitivamente"), card);
    erase_->setProperty("danger", true);
    restoreTo_ = new QPushButton(icon(QStringLiteral("folder")), QStringLiteral("Restaurar em…"), card);
    restore_ = new QPushButton(icon(QStringLiteral("rotate-ccw")), QStringLiteral("Restaurar no local original"), card);
    for (QPushButton* b : {erase_, restoreTo_, restore_}) actions->addWidget(b);
    card->body()->addLayout(actions);
    status_ = mutedLabel(QString(), card);
    card->body()->addWidget(status_);
    col->addWidget(card);
    col->addStretch();

    auto* q = ctx_->quarantine();
    connect(q, &gk::bridge::QuarantineService::listed, this, [this](qint64 request, const QJsonArray& items) {
        if (request != listRequest_) return;
        listRequest_ = -1;
        items_ = items;
        const QString previous = selectedId();
        table_->setRowCount(0);
        for (const auto& v : items) {
            const QJsonObject it = v.toObject();
            const int row = table_->rowCount();
            table_->insertRow(row);
            static const QStringList levels{"NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
            const QString level = levels.value(it.value("risk").toInt(), QStringLiteral("NONE"));
            auto* when = cell(scanWhen(it.value("quarantined_at")));
            when->setData(Qt::UserRole, it.value("id").toString());
            auto* risk = cell(riskLabel(level));
            risk->setForeground(riskColor(level));
            const QString cls = it.value("classification").toString();
            table_->setItem(row, 0, when);
            table_->setItem(row, 1, cell(QDir::toNativeSeparators(it.value("original_path").toString())));
            table_->setItem(row, 2, risk);
            table_->setItem(row, 3, cell(cls.isEmpty() ? QStringLiteral("—") : ctx_->catalog().classification(cls)));
            table_->setItem(row, 4, cell(it.value("detection").toString()));
            table_->setItem(row, 5, cell(it.value("reason").toString()));
            table_->setItem(row, 6, cell(statusLabel(it.value("status").toString())));
        }
        fitTableToContents(table_, 12);
        table_->setVisible(!items.isEmpty());
        empty_->setVisible(items.isEmpty());
        if (!previous.isEmpty()) selectItem(previous);
        else if (table_->rowCount() > 0) table_->selectRow(0);
        updateButtons();
        emit listed(table_->rowCount());
    });
    connect(q, &gk::bridge::QuarantineService::finished, this, &QuarantinePage::onFinished);
    connect(showFinished_, &QCheckBox::toggled, this, &QuarantinePage::refresh);
    connect(table_, &QTableWidget::itemSelectionChanged, this, &QuarantinePage::updateButtons);
    connect(restore_, &QPushButton::clicked, this, [this] { restoreSelected(); });
    connect(restoreTo_, &QPushButton::clicked, this, [this] {
        const QString dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Restaurar na pasta"));
        if (dir.isEmpty()) return;
        for (const auto& v : items_) {
            const QJsonObject it = v.toObject();
            if (it.value("id").toString() == selectedId())
                restoreSelected(QDir(dir).filePath(QFileInfo(it.value("original_path").toString()).fileName()));
        }
    });
    connect(erase_, &QPushButton::clicked, this, &QuarantinePage::eraseSelected);
    connect(verify_, &QPushButton::clicked, this, &QuarantinePage::verifyVault);
    updateButtons();
    refresh();
}

void QuarantinePage::refresh() {
    if (listRequest_ < 0) listRequest_ = ctx_->quarantine()->list(showFinished_->isChecked());
}

void QuarantinePage::setShowFinished(bool on) { showFinished_->setChecked(on); }

int QuarantinePage::itemCount() const { return table_->rowCount(); }

QString QuarantinePage::selectedId() const {
    const auto rows = table_->selectionModel() ? table_->selectionModel()->selectedRows() : QModelIndexList{};
    if (rows.isEmpty()) return {};
    return table_->item(rows.first().row(), 0)->data(Qt::UserRole).toString();
}

bool QuarantinePage::selectItem(const QString& id) {
    for (int row = 0; row < table_->rowCount(); ++row) {
        if (table_->item(row, 0)->data(Qt::UserRole).toString() == id) {
            table_->selectRow(row);
            return true;
        }
    }
    return false;
}

bool QuarantinePage::restoreSelected(const QString& destination) {
    const QString id = selectedId();
    if (id.isEmpty() || opRequest_ >= 0) return false;
    QString original;
    for (const auto& v : items_)
        if (v.toObject().value("id").toString() == id) original = v.toObject().value("original_path").toString();
    const QString target = destination.isEmpty() ? original : destination;
    if (!ctx_->ask(this, QStringLiteral("Restaurar arquivo"),
                   QStringLiteral("Restaurar \"%1\"?\n\nO arquivo volta a poder ser executado. Restaure só o que você tem "
                                  "certeza de que é seguro (por exemplo, um falso positivo).")
                       .arg(QDir::toNativeSeparators(target))))
        return false;
    pendingRestoreId_ = id;
    pendingRestoreTo_ = destination;
    opRequest_ = ctx_->quarantine()->restore(id, destination, false);
    status_->setText(QStringLiteral("Restaurando…"));
    updateButtons();
    return true;
}

bool QuarantinePage::eraseSelected() {
    const QString id = selectedId();
    if (id.isEmpty() || opRequest_ >= 0) return false;
    if (!ctx_->ask(this, QStringLiteral("Apagar definitivamente"),
                   QStringLiteral("Apagar definitivamente o item selecionado da quarentena? Esta ação não pode ser desfeita.")))
        return false;
    opRequest_ = ctx_->quarantine()->erase(id);
    status_->setText(QStringLiteral("Apagando…"));
    updateButtons();
    return true;
}

void QuarantinePage::verifyVault() {
    if (opRequest_ >= 0) return;
    opRequest_ = ctx_->quarantine()->verify();
    status_->setText(QStringLiteral("Verificando o cofre…"));
    updateButtons();
}

void QuarantinePage::onFinished(qint64 request, const QString& kind, bool ok, const QJsonObject& result, const QString& message) {
    if (request != opRequest_) return;
    opRequest_ = -1;
    QString text;
    if (!ok && kind == QLatin1String("restore") && message.contains(QStringLiteral("já existe"))) {
        // The destination is taken: replacing it is a separate, explicit decision.
        if (ctx_->ask(this, QStringLiteral("Substituir arquivo"),
                      QStringLiteral("%1\n\nSubstituir o arquivo existente pelo da quarentena?").arg(message))) {
            opRequest_ = ctx_->quarantine()->restore(pendingRestoreId_, pendingRestoreTo_, true);
            status_->setText(QStringLiteral("Restaurando…"));
            updateButtons();
            return;
        }
        text = QStringLiteral("Restauração cancelada: o arquivo existente foi mantido.");
    } else if (!ok) {
        text = QStringLiteral("A operação não foi concluída: %1").arg(message);
    } else if (kind == QLatin1String("restore")) {
        text = QStringLiteral("Restaurado em %1.").arg(QDir::toNativeSeparators(result.value("restored_to").toString()));
    } else if (kind == QLatin1String("erase")) {
        text = QStringLiteral("Item apagado definitivamente.");
    } else if (kind == QLatin1String("verify")) {
        const int damaged = result.value("damaged").toArray().size();
        text = QStringLiteral("Cofre verificado: %1 item(ns) íntegro(s), %2 danificado(s), %3 recuperado(s).")
                   .arg(result.value("ok").toArray().size())
                   .arg(damaged)
                   .arg(result.value("recovered").toArray().size());
        ok = damaged == 0;
    } else {
        return;   // quarantine operations started by other pages
    }
    status_->setText(text);
    emit ctx_->notify(ok ? AppContext::Level::Success : AppContext::Level::Error, QStringLiteral("Quarentena"), text);
    refresh();
    updateButtons();
    emit operationFinished(kind, ok, text);
}

void QuarantinePage::updateButtons() {
    QString status;
    for (const auto& v : items_)
        if (v.toObject().value("id").toString() == selectedId()) status = v.toObject().value("status").toString();
    const bool active = status == QLatin1String("quarantined") && opRequest_ < 0;
    restore_->setEnabled(active);
    restoreTo_->setEnabled(active);
    erase_->setEnabled(active);
    verify_->setEnabled(opRequest_ < 0);
}

}  // namespace gk::app
