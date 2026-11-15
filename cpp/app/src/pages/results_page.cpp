#include "results_page.hpp"

#include "../ui_kit.hpp"
#include "scan_table.hpp"

#include <QComboBox>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLocale>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableWidget>
#include <QUrl>

namespace gk::app {

namespace {

constexpr int kRowIndex = Qt::UserRole;   // index into results_ stored on column 0

QTableWidgetItem* cell(const QString& text) {
    auto* item = new QTableWidgetItem(text);
    item->setToolTip(text);
    return item;
}

QString where(const QJsonObject& r) {
    const QString container = r.value("container").toString();
    if (!container.isEmpty())
        return QStringLiteral("%1 → %2").arg(QDir::toNativeSeparators(container), r.value("member_path").toString());
    return QDir::toNativeSeparators(r.value("directory").toString());
}

QString locationText(const QJsonObject& loc) {
    const QString kind = loc.value("kind").toString();
    QStringList parts;
    if (loc.contains("line")) parts << QStringLiteral("linha %1").arg(loc.value("line").toInt());
    if (loc.contains("offset")) parts << QStringLiteral("posição 0x%1").arg(QString::number(loc.value("offset").toInteger(), 16));
    if (loc.contains("section")) parts << QStringLiteral("seção %1").arg(loc.value("section").toString());
    if (parts.isEmpty() && !kind.isEmpty()) parts << kind;
    QString text = parts.join(QStringLiteral(", "));
    const QString excerpt = loc.value("excerpt").toString();
    if (!excerpt.isEmpty()) text += QStringLiteral(": ") + excerpt.left(80);
    return text;
}

QString escape(const QString& s) { return s.toHtmlEscaped(); }

}  // namespace

ResultsPage::ResultsPage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);

    auto* scanCard = new Card(QStringLiteral("Varredura"), content);
    scanLine_ = new QLabel(QStringLiteral("Nenhuma varredura carregada."), scanCard);
    scanLine_->setWordWrap(true);
    scanCard->body()->addWidget(scanLine_);
    limitations_ = mutedLabel(QString(), scanCard);
    scanCard->body()->addWidget(limitations_);
    auto* scanRow = new QHBoxLayout;
    scanRow->addWidget(new QLabel(QStringLiteral("Mostrar:"), scanCard));
    filter_ = new QComboBox(scanCard);
    filter_->addItem(QStringLiteral("Tudo o que merece atenção"), QString());
    for (const char* code : {"malware", "suspicious", "pua", "inconclusive", "modified"})
        filter_->addItem(ctx_->catalog().classification(QString::fromLatin1(code)), QString::fromLatin1(code));
    scanRow->addWidget(filter_);
    scanRow->addStretch();
    report_ = new QPushButton(icon(QStringLiteral("file-text")), QStringLiteral("Gerar relatório"), scanCard);
    auto* reload = new QPushButton(icon(QStringLiteral("refresh")), QStringLiteral("Atualizar"), scanCard);
    scanRow->addWidget(report_);
    scanRow->addWidget(reload);
    scanCard->body()->addLayout(scanRow);
    col->addWidget(scanCard);

    auto* listCard = new Card(QStringLiteral("Achados"), content);
    table_ = makeTable({"Risco", "Classificação", "Arquivo", "Categoria", "Crack ou mod", "Local"}, listCard);
    table_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    table_->setTextElideMode(Qt::ElideMiddle);
    table_->setWordWrap(false);
    listCard->body()->addWidget(table_);
    empty_ = mutedLabel(QString(), listCard);
    empty_->setVisible(false);
    listCard->body()->addWidget(empty_);
    col->addWidget(listCard);

    auto* detailCard = new Card(QStringLiteral("Detalhes"), content);
    auto* titleRow = new QHBoxLayout;
    detailTitle_ = new QLabel(QStringLiteral("Escolha um arquivo na lista."), detailCard);
    detailTitle_->setObjectName(QStringLiteral("cardTitle"));
    detailRisk_ = new StatusPill(QString(), StatusPill::Tone::Neutral, detailCard);
    detailRisk_->setVisible(false);
    titleRow->addWidget(detailTitle_, 1);
    titleRow->addWidget(detailRisk_);
    detailCard->body()->addLayout(titleRow);
    detail_ = new QLabel(detailCard);
    detail_->setWordWrap(true);
    detail_->setTextFormat(Qt::RichText);
    detail_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    detailCard->body()->addWidget(detail_);
    detailCard->body()->addWidget(new QLabel(QStringLiteral("Evidências"), detailCard));
    evidences_ = makeTable({"Severidade", "Evidência", "Fonte", "Regra", "Onde", "Falso positivo possível"}, detailCard);
    evidences_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    detailCard->body()->addWidget(evidences_);
    auto* actions = new QHBoxLayout;
    actions->addStretch();
    openFolder_ = new QPushButton(icon(QStringLiteral("folder")), QStringLiteral("Abrir a pasta do arquivo"), detailCard);
    quarantine_ = new QPushButton(icon(QStringLiteral("lock"), Qt::white), QStringLiteral("Colocar em quarentena"), detailCard);
    quarantine_->setProperty("danger", true);
    actions->addWidget(openFolder_);
    actions->addWidget(quarantine_);
    detailCard->body()->addLayout(actions);
    col->addWidget(detailCard);
    col->addStretch();
    fitTableToContents(table_);
    fitTableToContents(evidences_);

    connect(ctx_->history(), &gk::bridge::HistoryService::scanLoaded, this,
            [this](qint64 request, const QJsonObject& scan, const QJsonArray& results) {
                if (request == loadRequest_) {
                    loadRequest_ = -1;
                    showScan(scan, results);
                }
            });
    connect(ctx_->history(), &gk::bridge::HistoryService::scansListed, this, [this](qint64 request, const QJsonArray& scans) {
        if (request != latestRequest_) return;
        latestRequest_ = -1;
        if (scans.isEmpty()) {
            showScan({}, {});
            return;
        }
        loadScan(scans.first().toObject().value("scan_id").toInteger());
    });
    connect(ctx_->history(), &gk::bridge::HistoryService::failed, this, [this](qint64 request, const QString& message) {
        if (request != loadRequest_ && request != latestRequest_) return;
        loadRequest_ = latestRequest_ = -1;
        scanLine_->setText(QStringLiteral("Não foi possível ler a varredura: %1").arg(message));
        emit loaded(0);
    });
    connect(ctx_->quarantine(), &gk::bridge::QuarantineService::finished, this,
            [this](qint64 request, const QString&, bool ok, const QJsonObject&, const QString& message) {
                if (request != quarantineRequest_) return;
                quarantineRequest_ = -1;
                const QString text = ok ? QStringLiteral("Arquivo colocado em quarentena. Ele pode ser restaurado na página Quarentena.")
                                        : QStringLiteral("O arquivo não foi colocado em quarentena: %1").arg(message);
                emit ctx_->notify(ok ? AppContext::Level::Success : AppContext::Level::Error, QStringLiteral("Quarentena"), text);
                updateButtons();
                emit quarantineFinished(ok, text);
            });
    connect(filter_, &QComboBox::currentIndexChanged, this, &ResultsPage::applyFilter);
    connect(table_, &QTableWidget::itemSelectionChanged, this, &ResultsPage::showDetail);
    connect(reload, &QPushButton::clicked, this, [this] { scanId_ > 0 ? loadScan(scanId_) : loadLatest(); });
    connect(report_, &QPushButton::clicked, this, [this] {
        if (scanId_ > 0) emit openReports(scanId_);
    });
    connect(openFolder_, &QPushButton::clicked, this, [this] {
        const QJsonObject r = selectedResult();
        const QString file = r.value("container").toString().isEmpty() ? r.value("path").toString() : r.value("container").toString();
        if (!file.isEmpty()) QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(file).absolutePath()));
    });
    connect(quarantine_, &QPushButton::clicked, this, &ResultsPage::quarantineSelected);
    updateButtons();
}

void ResultsPage::loadScan(qint64 scanId) {
    latestRequest_ = -1;   // an explicit choice wins over a pending "load the latest scan"
    scanId_ = scanId;
    loadRequest_ = ctx_->history()->loadScan(scanId, true);
}

void ResultsPage::loadLatest() { latestRequest_ = ctx_->history()->listScans(1); }

void ResultsPage::showScan(const QJsonObject& scan, const QJsonArray& results) {
    scan_ = scan;
    results_ = results;
    if (scan.isEmpty()) {
        scanId_ = -1;
        scanLine_->setText(QStringLiteral("Nenhuma varredura registrada ainda. Faça uma em Segurança do jogo."));
        limitations_->clear();
    } else {
        scanId_ = scan.value("scan_id").toInteger();
        QStringList targets;
        for (const auto& t : scan.value("targets").toArray()) targets << QDir::toNativeSeparators(t.toString());
        const QString level = scan.value("max_risk_level").toString();
        scanLine_->setText(QStringLiteral("Varredura nº %1 — %2, %3, %4. Alvos: %5. Arquivos: %6; ameaças: %7; suspeitos ou PUA: %8. "
                                          "Risco máximo: <span style='color:%9'>%10</span>.")
                               .arg(scanId_)
                               .arg(scanWhen(scan.value("started_at")), scanModeLabel(scan.value("mode").toString()).toLower(),
                                    scanStatusLabel(scan.value("status").toString()).toLower(), escape(targets.join(QStringLiteral("; "))))
                               .arg(scan.value("files_found").toInteger())
                               .arg(scan.value("threats").toInteger())
                               .arg(scan.value("suspicious").toInteger() + scan.value("pua").toInteger())
                               .arg(riskColor(level).name(), riskLabel(level)));
        QStringList notes;
        for (const auto& l : scan.value("summary").toObject().value("limitations").toArray()) notes << QStringLiteral("• ") + l.toString();
        for (const auto& w : scan.value("summary").toObject().value("warnings").toArray()) notes << QStringLiteral("⚠ ") + w.toString();
        limitations_->setText(notes.join('\n'));
    }
    applyFilter();
    updateButtons();
    emit loaded(findingsCount());
}

void ResultsPage::applyFilter() {
    const QString wanted = filter_->currentData().toString();
    const auto& catalog = ctx_->catalog();
    table_->setRowCount(0);
    for (int i = 0; i < results_.size(); ++i) {
        const QJsonObject r = results_.at(i).toObject();
        if (!wanted.isEmpty() && r.value("classification").toString() != wanted) continue;
        const int row = table_->rowCount();
        table_->insertRow(row);
        const QString risk = r.value("risk").toString();
        auto* riskItem = cell(riskLabel(risk));
        riskItem->setForeground(riskColor(risk));
        riskItem->setData(kRowIndex, i);
        const QString crack = r.value("crack_status").toString();
        const QStringList texts{catalog.classification(r.value("classification").toString()), r.value("name").toString(),
                                r.value("primary_category").isString() ? catalog.categoryLabel(r.value("primary_category").toString())
                                                                       : QStringLiteral("—"),
                                crack == QLatin1String("none") || crack.isEmpty() ? QStringLiteral("—") : catalog.crackStatus(crack),
                                where(r)};
        table_->setItem(row, 0, riskItem);
        for (int c = 0; c < texts.size(); ++c) table_->setItem(row, c + 1, cell(texts[c]));
    }
    const bool none = table_->rowCount() == 0;
    empty_->setVisible(none && !scan_.isEmpty());
    empty_->setText(results_.isEmpty() ? QStringLiteral("Nada que mereça atenção nesta varredura: nenhum arquivo com risco, "
                                                        "classificação suspeita ou análise incompleta.")
                                       : QStringLiteral("Nenhum arquivo com essa classificação."));
    fitTableToContents(table_, 12);
    if (!none) table_->selectRow(0);
    else showDetail();
}

int ResultsPage::findingsCount() const { return table_->rowCount(); }

void ResultsPage::setFilter(const QString& classification) {
    const int index = filter_->findData(classification);
    filter_->setCurrentIndex(index < 0 ? 0 : index);
}

bool ResultsPage::selectFile(const QString& name) {
    for (int row = 0; row < table_->rowCount(); ++row) {
        if (table_->item(row, 2)->text() == name) {
            table_->selectRow(row);
            return true;
        }
    }
    return false;
}

QJsonObject ResultsPage::selectedResult() const {
    const auto rows = table_->selectionModel() ? table_->selectionModel()->selectedRows() : QModelIndexList{};
    if (rows.isEmpty()) return {};
    const int index = table_->item(rows.first().row(), 0)->data(kRowIndex).toInt();
    return results_.at(index).toObject();
}

QString ResultsPage::detailText() const {
    QString plain = detail_->text();
    plain.replace(QStringLiteral("<br>"), QStringLiteral("\n"));
    plain.remove(QRegularExpression(QStringLiteral("<[^>]*>")));
    return detailTitle_->text() + '\n' + plain;
}

void ResultsPage::showDetail() {
    const QJsonObject r = selectedResult();
    evidences_->setRowCount(0);
    if (r.isEmpty()) {
        detailTitle_->setText(QStringLiteral("Escolha um arquivo na lista."));
        detailRisk_->setVisible(false);
        detail_->clear();
        fitTableToContents(evidences_);
        updateButtons();
        return;
    }
    const auto& catalog = ctx_->catalog();
    const QString risk = r.value("risk").toString();
    detailTitle_->setText(r.value("name").toString());
    detailRisk_->set(QStringLiteral("%1 · %2").arg(riskLabel(risk), catalog.classification(r.value("classification").toString())),
                     risk == QLatin1String("CRITICAL") || risk == QLatin1String("HIGH") ? StatusPill::Tone::Bad
                     : risk == QLatin1String("MEDIUM") || risk == QLatin1String("LOW")  ? StatusPill::Tone::Warning
                                                                                        : StatusPill::Tone::Neutral);
    detailRisk_->setVisible(true);

    QStringList html;
    auto row = [&html](const QString& label, const QString& value) {
        if (!value.isEmpty()) html << QStringLiteral("<b>%1:</b> %2").arg(label, value.toHtmlEscaped());
    };
    row(QStringLiteral("Caminho"), QDir::toNativeSeparators(r.value("path").toString()));
    if (!r.value("container").toString().isEmpty()) {
        row(QStringLiteral("Dentro do compactado"), QDir::toNativeSeparators(r.value("container").toString()));
        row(QStringLiteral("Caminho no compactado"), r.value("member_path").toString());
    }
    row(QStringLiteral("SHA-256"), r.value("sha256").toString());
    row(QStringLiteral("Tamanho"), QLocale().formattedDataSize(r.value("size").toInteger()));
    row(QStringLiteral("Tipo"), r.value("file_type").toString());
    const QJsonObject features = r.value("features").toObject();
    if (features.value("signed").toBool()) {
        const QJsonValue valid = features.value("signature_valid");
        row(QStringLiteral("Assinatura digital"), valid.isBool() ? (valid.toBool() ? QStringLiteral("válida — %1").arg(features.value("signer").toString())
                                                                               : QStringLiteral("presente, inválida"))
                                                               : QStringLiteral("presente, não verificada"));
    } else if (features.value("is_pe").toBool()) {
        row(QStringLiteral("Assinatura digital"), QStringLiteral("ausente"));
    }
    const QString crack = r.value("crack_status").toString();
    if (!crack.isEmpty() && crack != QLatin1String("none")) row(QStringLiteral("Crack ou mod"), catalog.crackStatus(crack));
    if (r.value("status").toString() != QLatin1String("complete")) {
        QStringList reasons;
        for (const auto& v : r.value("status_reasons").toArray()) reasons << v.toString();
        row(QStringLiteral("Análise incompleta"), reasons.join(QStringLiteral("; ")));
    }
    if (r.value("possible_false_positive").toBool())
        html << QStringLiteral("<b>Falso positivo possível:</b> as evidências também ocorrem em programas legítimos; veja as notas abaixo.");
    const QString category = r.value("primary_category").toString();
    if (!category.isEmpty()) {
        const QJsonObject info = catalog.category(category);
        row(QStringLiteral("Categoria"), catalog.categoryLabel(category));
        row(QStringLiteral("O que pode fazer"), info.value("can_do").toString());
        row(QStringLiteral("Dados em risco"), info.value("data_at_risk").toString());
    }
    QStringList why, todo;
    for (const auto& v : r.value("explanation").toArray()) why << QStringLiteral("• ") + v.toString().toHtmlEscaped();
    for (const auto& v : r.value("recommendations").toArray()) todo << QStringLiteral("• ") + v.toString().toHtmlEscaped();
    if (!why.isEmpty()) html << QStringLiteral("<br><b>Por que</b><br>") + why.join(QStringLiteral("<br>"));
    if (!todo.isEmpty()) html << QStringLiteral("<br><b>O que fazer</b><br>") + todo.join(QStringLiteral("<br>"));
    detail_->setText(html.join(QStringLiteral("<br>")));

    for (const auto& v : r.value("evidences").toArray()) {
        const QJsonObject e = v.toObject();
        const int i = evidences_->rowCount();
        evidences_->insertRow(i);
        const QString sev = e.value("adjusted_severity").isString() ? e.value("adjusted_severity").toString()
                                                                    : e.value("severity").toString();
        auto* sevItem = cell(riskLabel(sev));
        sevItem->setForeground(riskColor(sev));
        QStringList places;
        for (const auto& l : e.value("locations").toArray()) places << locationText(l.toObject());
        evidences_->setItem(i, 0, sevItem);
        evidences_->setItem(i, 1, cell(e.value("title").toString()));
        evidences_->setItem(i, 2, cell(catalog.evidenceSource(e.value("source").toString())));
        evidences_->setItem(i, 3, cell(e.value("rule_id").toString()));
        evidences_->setItem(i, 4, cell(places.join(QStringLiteral("; "))));
        evidences_->setItem(i, 5, cell(e.value("fp_note").toString()));
    }
    fitTableToContents(evidences_, 12);
    updateButtons();
}

void ResultsPage::updateButtons() {
    const QJsonObject r = selectedResult();
    quarantine_->setEnabled(!r.isEmpty() && quarantineRequest_ < 0);
    quarantine_->setText(r.value("container").toString().isEmpty() ? QStringLiteral("Colocar em quarentena")
                                                                    : QStringLiteral("Colocar o compactado em quarentena"));
    openFolder_->setEnabled(!r.isEmpty());
    report_->setEnabled(scanId_ > 0);
}

bool ResultsPage::quarantineSelected() {
    const QJsonObject r = selectedResult();
    if (r.isEmpty() || quarantineRequest_ >= 0) return false;
    const bool member = !r.value("container").toString().isEmpty();
    const QString file = member ? r.value("container").toString() : r.value("path").toString();
    QString expected;
    if (member) {   // the archive itself, as analysed (its own result carries its SHA-256)
        for (const auto& v : results_)
            if (v.toObject().value("path").toString() == file) expected = v.toObject().value("sha256").toString();
    } else {
        expected = r.value("sha256").toString();
    }
    const QString text =
        QStringLiteral("Mover \"%1\" para a quarentena?\n\nO arquivo sai da pasta e fica guardado criptografado neste computador; você "
                       "pode restaurá-lo na página Quarentena. Se o jogo depender dele, pode parar de funcionar.%2")
            .arg(QDir::toNativeSeparators(file),
                 member ? QStringLiteral("\n\nO arquivo encontrado está dentro de um compactado: o compactado inteiro será movido.")
                        : QString());
    if (!ctx_->ask(this, QStringLiteral("Colocar em quarentena"), text)) return false;
    gk::bridge::QuarantineService::Item item;
    item.path = file;
    item.expectedSha256 = expected;   // refused if the file changed since it was analysed
    item.reason = QStringLiteral("Análise forense, varredura %1").arg(scanId_);
    item.classification = r.value("classification").toString();
    QStringList rules;
    for (const auto& e : r.value("evidences").toArray()) rules << e.toObject().value("rule_id").toString();
    item.detection = rules.mid(0, 5).join(QStringLiteral(", "));
    static const QStringList levels{"NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    item.risk = std::max(0, int(levels.indexOf(r.value("risk").toString())));
    item.scanId = scanId_ > 0 ? scanId_ : 0;
    quarantineRequest_ = ctx_->quarantine()->quarantine(item);
    updateButtons();
    return true;
}

}  // namespace gk::app
