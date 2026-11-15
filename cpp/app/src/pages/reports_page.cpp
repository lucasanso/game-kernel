#include "reports_page.hpp"

#include "../ui_kit.hpp"

#include <QCheckBox>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QLabel>
#include <QLocale>
#include <QProgressBar>
#include <QPushButton>
#include <QTableWidget>
#include <QUrl>

namespace gk::app {

namespace {

QString when(const QString& iso) {
    const QDateTime t = QDateTime::fromString(iso, Qt::ISODate);
    return t.isValid() ? t.toLocalTime().toString(QStringLiteral("dd/MM/yyyy HH:mm")) : QStringLiteral("—");
}

QString modeLabel(const QString& mode) {
    if (mode == QLatin1String("deep")) return QStringLiteral("Completa");
    if (mode == QLatin1String("quick")) return QStringLiteral("Rápida");
    return mode;
}

QString statusLabel(const QString& status) {
    static const QHash<QString, QString> labels{{"completed", "Concluída"}, {"cancelled", "Cancelada"},
                                                {"failed", "Falhou"},       {"running", "Em andamento"},
                                                {"interrupted", "Interrompida"}};
    return labels.value(status, status);
}

QString stageLabel(const QString& stage) {
    static const QHash<QString, QString> labels{{"load", "Lendo a varredura no banco…"}, {"json", "Gerando o JSON…"},
                                                {"html", "Gerando o HTML…"},             {"pdf", "Gerando o PDF…"}};
    return labels.value(stage, stage);
}

QTableWidgetItem* cell(const QString& text) {
    auto* item = new QTableWidgetItem(text);
    item->setToolTip(text);
    return item;
}

void openLocal(const QString& path) {
    // Local file or folder in the user's default program; no URL other than file:// is ever opened.
    QDesktopServices::openUrl(QUrl::fromLocalFile(path));
}

}  // namespace

ReportsPage::ReportsPage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);

    // ---- scans recorded in the database
    auto* scansCard = new Card(QStringLiteral("Varreduras registradas"), content);
    auto* scansHeader = new QHBoxLayout;
    scansHeader->addWidget(mutedLabel(QStringLiteral("Escolha a varredura do relatório. A lista vem do banco local, "
                                                     "lido sem nenhuma alteração."),
                                      scansCard),
                           1);
    auto* refreshButton = new QPushButton(icon(QStringLiteral("refresh")), QStringLiteral("Atualizar"), scansCard);
    scansHeader->addWidget(refreshButton, 0, Qt::AlignTop);
    scansCard->body()->addLayout(scansHeader);
    scans_ = makeTable({"Nº", "Início", "Modo", "Alvos", "Arquivos", "Ameaças", "Suspeitos", "Risco máximo", "Situação"},
                       scansCard);
    // Paths are the long column: they stretch and are elided in the middle; the status fits its text.
    scans_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    scans_->horizontalHeader()->setSectionResizeMode(8, QHeaderView::ResizeToContents);
    scans_->setTextElideMode(Qt::ElideMiddle);
    scans_->setWordWrap(false);
    scans_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scansCard->body()->addWidget(scans_);
    empty_ = mutedLabel(QString(), scansCard);
    empty_->setVisible(false);
    scansCard->body()->addWidget(empty_);
    col->addWidget(scansCard);

    // ---- generation
    auto* generateCard = new Card(QStringLiteral("Gerar relatório forense"), content);
    auto* formatsRow = new QHBoxLayout;
    formatsRow->addWidget(new QLabel(QStringLiteral("Formatos:"), generateCard));
    html_ = new QCheckBox(QStringLiteral("HTML (para ler)"), generateCard);
    json_ = new QCheckBox(QStringLiteral("JSON (para ferramentas)"), generateCard);
    pdf_ = new QCheckBox(QStringLiteral("PDF (para arquivar)"), generateCard);
    html_->setChecked(true);
    json_->setChecked(true);
    pdf_->setEnabled(false);                       // until reports.formats says PDF is available
    pdf_->setToolTip(QStringLiteral("Verificando se o PDF está disponível…"));
    for (QCheckBox* c : {html_, json_, pdf_}) formatsRow->addWidget(c);
    formatsRow->addStretch();
    generateCard->body()->addLayout(formatsRow);
    includeClean_ = new QCheckBox(QStringLiteral("Listar também os arquivos limpos (relatório maior)"), generateCard);
    keepUsername_ = new QCheckBox(QStringLiteral("Manter o nome de usuário nos caminhos (por padrão é ocultado)"), generateCard);
    keepUsername_->setChecked(!ctx_->setting(QStringLiteral("reports.redact_username"), true).toBool());
    includeHostname_ = new QCheckBox(QStringLiteral("Incluir o nome do computador"), generateCard);
    includeHostname_->setChecked(ctx_->setting(QStringLiteral("reports.include_hostname"), false).toBool());
    for (QCheckBox* c : {includeClean_, keepUsername_, includeHostname_}) generateCard->body()->addWidget(c);
    auto* actions = new QHBoxLayout;
    actions->addStretch();
    openReport_ = new QPushButton(icon(QStringLiteral("file-text")), QStringLiteral("Abrir relatório"), generateCard);
    generateButton_ = new QPushButton(icon(QStringLiteral("file-text"), Qt::white),
                                      QStringLiteral("Gerar relatório da varredura escolhida"), generateCard);
    generateButton_->setProperty("primary", true);
    actions->addWidget(openReport_);
    actions->addWidget(generateButton_);
    generateCard->body()->addLayout(actions);
    progress_ = new QProgressBar(generateCard);
    progress_->setRange(0, 0);
    progress_->setVisible(false);
    generateCard->body()->addWidget(progress_);
    status_ = mutedLabel(QStringLiteral("Os relatórios trazem as 15 seções da análise e um relatório individual por "
                                        "crack. O HTML não tem scripts nem acessa a internet."),
                         generateCard);
    generateCard->body()->addWidget(status_);
    col->addWidget(generateCard);

    // ---- files already generated
    auto* filesCard = new Card(QStringLiteral("Relatórios gerados"), content);
    auto* filesHeader = new QHBoxLayout;
    filesHeader->addWidget(mutedLabel(QStringLiteral("Clique duas vezes para abrir. Pasta: %1").arg(QDir::toNativeSeparators(reportsDir())),
                                      filesCard),
                           1);
    auto* openFolder = new QPushButton(icon(QStringLiteral("folder")), QStringLiteral("Abrir pasta"), filesCard);
    filesHeader->addWidget(openFolder, 0, Qt::AlignTop);
    filesCard->body()->addLayout(filesHeader);
    files_ = makeTable({"Arquivo", "Formato", "Tamanho", "Gerado em"}, filesCard);
    filesCard->body()->addWidget(files_);
    col->addWidget(filesCard);
    col->addStretch();

    auto* helper = ctx_->helper();
    connect(helper, &gk::ipc::HelperClient::callSucceeded, this, &ReportsPage::onSucceeded);
    connect(helper, &gk::ipc::HelperClient::callFailed, this, &ReportsPage::onFailed);
    connect(helper, &gk::ipc::HelperClient::eventReceived, this, &ReportsPage::onEvent);
    connect(refreshButton, &QPushButton::clicked, this, &ReportsPage::refresh);
    connect(generateButton_, &QPushButton::clicked, this, &ReportsPage::generate);
    connect(openReport_, &QPushButton::clicked, this, [this] {
        if (!lastReport_.isEmpty()) openLocal(lastReport_);
    });
    connect(openFolder, &QPushButton::clicked, this, [this] {
        QDir().mkpath(reportsDir());
        openLocal(reportsDir());
    });
    connect(files_, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (auto* item = files_->item(row, 0)) openLocal(item->data(Qt::UserRole).toString());
    });
    connect(scans_, &QTableWidget::itemSelectionChanged, this, &ReportsPage::updateButtons);
    connect(ctx_, &AppContext::settingChanged, this, [this](const QString& key) {   // new defaults from Configurações
        if (key == QLatin1String("reports.redact_username"))
            keepUsername_->setChecked(!ctx_->setting(key, true).toBool());
        else if (key == QLatin1String("reports.include_hostname"))
            includeHostname_->setChecked(ctx_->setting(key, false).toBool());
    });
    for (QCheckBox* c : {html_, json_, pdf_}) connect(c, &QCheckBox::toggled, this, &ReportsPage::updateButtons);
    updateButtons();
    refresh();
}

QString ReportsPage::reportsDir() const { return QDir(ctx_->dataDir()).filePath(QStringLiteral("reports")); }

void ReportsPage::refresh() {
    auto* helper = ctx_->helper();
    if (formatsCall_ < 0) formatsCall_ = helper->call(QStringLiteral("reports.formats"), {}, 30000);
    if (scansCall_ < 0) scansCall_ = helper->call(QStringLiteral("reports.scans"), {{"limit", 200}}, 60000);
    listGeneratedFiles();
}

qint64 ReportsPage::selectedScan() const {
    const auto rows = scans_->selectionModel() ? scans_->selectionModel()->selectedRows() : QModelIndexList{};
    if (rows.isEmpty()) return -1;
    const QTableWidgetItem* item = scans_->item(rows.first().row(), 0);
    return item ? item->data(Qt::UserRole).toLongLong() : -1;
}

bool ReportsPage::selectScan(qint64 scanId) {
    for (int row = 0; row < scans_->rowCount(); ++row) {
        if (scans_->item(row, 0)->data(Qt::UserRole).toLongLong() == scanId) {
            scans_->selectRow(row);
            return true;
        }
    }
    return false;
}

int ReportsPage::scanCount() const { return scans_->rowCount(); }

QString ReportsPage::emptyStateText() const { return empty_->isVisibleTo(this) ? empty_->text() : QString(); }

QStringList ReportsPage::generatedFiles() const {
    QStringList names;
    for (int row = 0; row < files_->rowCount(); ++row) names << files_->item(row, 0)->text();
    return names;
}

bool ReportsPage::generate() {
    const qint64 scanId = selectedScan();
    QJsonArray formats;
    if (html_->isChecked()) formats.append(QStringLiteral("html"));
    if (json_->isChecked()) formats.append(QStringLiteral("json"));
    if (pdf_->isChecked() && pdf_->isEnabled()) formats.append(QStringLiteral("pdf"));
    if (scanId < 0 || formats.isEmpty() || generateCall_ >= 0) {
        status_->setText(scanId < 0 ? QStringLiteral("Escolha uma varredura na lista acima.")
                                    : QStringLiteral("Escolha pelo menos um formato."));
        updateButtons();
        return false;
    }
    const QJsonObject params{{"scan_id", scanId},
                             {"formats", formats},
                             {"include_clean", includeClean_->isChecked()},
                             {"redact_username", !keepUsername_->isChecked()},
                             {"include_hostname", includeHostname_->isChecked()}};
    generateCall_ = ctx_->helper()->call(QStringLiteral("reports.generate"), params, 300000);
    progress_->setVisible(true);
    status_->setText(QStringLiteral("Gerando o relatório da varredura %1…").arg(scanId));
    updateButtons();
    return true;
}

void ReportsPage::updateButtons() {
    const bool anyFormat = html_->isChecked() || json_->isChecked() || (pdf_->isChecked() && pdf_->isEnabled());
    generateButton_->setEnabled(selectedScan() >= 0 && anyFormat && generateCall_ < 0);
    openReport_->setEnabled(!lastReport_.isEmpty() && QFileInfo::exists(lastReport_));
}

void ReportsPage::showScans(const QJsonArray& scans, bool databasePresent) {
    const qint64 previous = selectedScan();
    scans_->setRowCount(0);
    for (const auto& v : scans) {
        const QJsonObject s = v.toObject();
        const int row = scans_->rowCount();
        scans_->insertRow(row);
        auto* id = cell(QString::number(s.value("scan_id").toInteger()));
        id->setData(Qt::UserRole, s.value("scan_id").toInteger());
        QStringList targets;
        for (const auto& t : s.value("targets").toArray()) targets << QDir::toNativeSeparators(t.toString());
        const QJsonObject risk = s.value("max_risk").toObject();
        auto* riskItem = cell(risk.value("label").toString());
        riskItem->setForeground(riskColor(risk.value("level").toString()));
        const QStringList texts{when(s.value("started_at").toString()), modeLabel(s.value("mode").toString()),
                                targets.join(QStringLiteral("; ")),
                                QString::number(s.value("files_found").toInteger()),
                                QString::number(s.value("threats").toInteger()),
                                QString::number(s.value("suspicious").toInteger() + s.value("pua").toInteger())};
        scans_->setItem(row, 0, id);
        for (int c = 0; c < texts.size(); ++c) scans_->setItem(row, c + 1, cell(texts[c]));
        scans_->setItem(row, 7, riskItem);
        QString status = statusLabel(s.value("status").toString());
        if (!s.value("error").toString().isEmpty()) status += QStringLiteral(" — ") + s.value("error").toString();
        scans_->setItem(row, 8, cell(status));
    }
    const bool none = scans.isEmpty();
    scans_->setVisible(!none);
    empty_->setVisible(none);
    if (none) {
        empty_->setText(databasePresent ? QStringLiteral("O banco não tem varreduras registradas.")
                                        : QStringLiteral("Nenhuma varredura registrada neste computador ainda. As "
                                                         "varreduras feitas com o gk-cli aparecem aqui (veja o guia de uso)."));
    }
    fitTableToContents(scans_);
    if (previous >= 0) selectScan(previous);
    else if (!none) scans_->selectRow(0);
    updateButtons();
    emit scansLoaded(scans_->rowCount());
}

void ReportsPage::listGeneratedFiles() {
    files_->setRowCount(0);
    const QFileInfoList list = QDir(reportsDir()).entryInfoList({"*.html", "*.json", "*.pdf"}, QDir::Files, QDir::Time);
    const QLocale locale;
    for (const QFileInfo& f : list) {
        const int row = files_->rowCount();
        files_->insertRow(row);
        auto* name = cell(f.fileName());
        name->setData(Qt::UserRole, f.absoluteFilePath());
        files_->setItem(row, 0, name);
        files_->setItem(row, 1, cell(f.suffix().toUpper()));
        files_->setItem(row, 2, cell(locale.formattedDataSize(f.size())));
        files_->setItem(row, 3, cell(f.lastModified().toString(QStringLiteral("dd/MM/yyyy HH:mm"))));
    }
    fitTableToContents(files_);
}

void ReportsPage::onSucceeded(qint64 id, const QJsonValue& result) {
    const QJsonObject r = result.toObject();
    if (id == formatsCall_) {
        formatsCall_ = -1;
        const bool pdf = r.value("formats").toArray().contains(QStringLiteral("pdf"));
        pdf_->setEnabled(pdf);
        pdf_->setToolTip(pdf ? QStringLiteral("PDF com fonte Unicode.")
                             : QStringLiteral("PDF indisponível: %1").arg(r.value("unavailable").toObject().value("pdf").toString()));
        updateButtons();
    } else if (id == scansCall_) {
        scansCall_ = -1;
        showScans(r.value("scans").toArray(), r.value("database_present").toBool());
    } else if (id == generateCall_) {
        generateCall_ = -1;
        progress_->setVisible(false);
        QStringList written;
        lastReport_.clear();
        for (const auto& v : r.value("files").toArray()) {
            const QJsonObject f = v.toObject();
            written << f.value("format").toString().toUpper();
            if (lastReport_.isEmpty() || f.value("format").toString() == QLatin1String("html"))
                lastReport_ = f.value("path").toString();
        }
        const QJsonObject risk = r.value("max_risk").toObject();
        QString message = QStringLiteral("Relatório da varredura %1 gerado (%2). Risco máximo: %3.")
                              .arg(r.value("scan_id").toInteger())
                              .arg(written.join(QStringLiteral(", ")), risk.value("label").toString());
        for (const auto& w : r.value("warnings").toArray()) message += QStringLiteral("\nAviso: ") + w.toString();
        status_->setText(message);
        listGeneratedFiles();
        updateButtons();
        emit ctx_->notify(AppContext::Level::Success, QStringLiteral("Relatório forense"), message);
        emit reportFinished(true, message);
    }
}

void ReportsPage::onFailed(qint64 id, const gk::ipc::CallError& error) {
    if (id == formatsCall_) {
        formatsCall_ = -1;
        pdf_->setToolTip(QStringLiteral("Processo auxiliar indisponível: %1").arg(error.message));
    } else if (id == scansCall_) {
        scansCall_ = -1;
        scans_->setRowCount(0);
        scans_->setVisible(false);
        empty_->setVisible(true);
        empty_->setText(QStringLiteral("Não foi possível ler as varreduras: %1").arg(error.message));
        updateButtons();
        emit scansLoaded(0);
    } else if (id == generateCall_) {
        generateCall_ = -1;
        progress_->setVisible(false);
        const QString message = QStringLiteral("O relatório não foi gerado: %1").arg(error.message);
        status_->setText(message);
        updateButtons();
        emit ctx_->notify(AppContext::Level::Error, QStringLiteral("Relatório forense"), message);
        emit reportFinished(false, message);
    }
}

void ReportsPage::onEvent(qint64 id, const QString& name, const QJsonObject& payload) {
    if (id == generateCall_ && name == QLatin1String("progress")) status_->setText(stageLabel(payload.value("stage").toString()));
}

}  // namespace gk::app
