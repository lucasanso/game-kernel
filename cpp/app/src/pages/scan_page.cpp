#include "scan_page.hpp"

#include "../ui_kit.hpp"

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QLabel>
#include <QListWidget>
#include <QProgressBar>
#include <QPushButton>
#include <QRadioButton>
#include <QTableWidget>

namespace gk::app {

namespace {

QString phaseLabel(const QString& phase) {
    static const QHash<QString, QString> labels{
        {"enumerating", "Listando os arquivos…"},     {"analyzing", "Analisando (processos isolados, nada é executado)…"},
        {"signatures", "Conferindo assinaturas do ClamAV…"}, {"context", "Avaliando o contexto (cracks, mods) e o risco…"},
        {"saving", "Gravando os resultados…"},          {"done", "Concluída."}};
    return labels.value(phase, phase);
}

// Worth showing while the scan runs: anything the user must look at.
bool isFinding(const QJsonObject& r) {
    const QString cls = r.value("classification").toString();
    const QString risk = r.value("risk").toString();
    return (cls != QLatin1String("known_legit") && cls != QLatin1String("unknown")) ||
           (risk != QLatin1String("NONE") && risk != QLatin1String("INFO"));
}

}  // namespace

ScanPage::ScanPage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);

    auto* what = new Card(QStringLiteral("O que analisar"), content);
    what->body()->addWidget(mutedLabel(QStringLiteral("Escolha a pasta do jogo, do crack, do repack, do mod ou um arquivo. "
                                                      "A análise só lê os arquivos: nada é executado, movido ou apagado."),
                                       what));
    auto* listRow = new QHBoxLayout;
    targets_ = new QListWidget(what);
    targets_->setMaximumHeight(110);
    listRow->addWidget(targets_, 1);
    auto* listButtons = new QVBoxLayout;
    auto* addFolder = new QPushButton(icon(QStringLiteral("folder")), QStringLiteral("Adicionar pasta…"), what);
    auto* addFile = new QPushButton(icon(QStringLiteral("file")), QStringLiteral("Adicionar arquivo…"), what);
    removeButton_ = new QPushButton(icon(QStringLiteral("x")), QStringLiteral("Remover"), what);
    for (QPushButton* b : {addFolder, addFile, removeButton_}) listButtons->addWidget(b);
    listButtons->addStretch();
    listRow->addLayout(listButtons);
    what->body()->addLayout(listRow);
    auto* modeRow = new QHBoxLayout;
    deep_ = new QRadioButton(QStringLiteral("Completa (todos os tipos, inclusive dentro de compactados)"), what);
    quick_ = new QRadioButton(QStringLiteral("Rápida (executáveis e scripts; compactados não são abertos)"), what);
    deep_->setChecked(ctx_->setting(QStringLiteral("scan.default_mode"), QStringLiteral("deep")).toString() != QLatin1String("quick"));
    quick_->setChecked(!deep_->isChecked());
    modeRow->addWidget(deep_);
    modeRow->addWidget(quick_);
    modeRow->addStretch();
    what->body()->addLayout(modeRow);
    auto* actions = new QHBoxLayout;
    actions->addStretch();
    cancelButton_ = new QPushButton(icon(QStringLiteral("stop")), QStringLiteral("Cancelar"), what);
    pauseButton_ = new QPushButton(icon(QStringLiteral("pause")), QStringLiteral("Pausar"), what);
    startButton_ = new QPushButton(icon(QStringLiteral("play"), Qt::white), QStringLiteral("Iniciar varredura"), what);
    startButton_->setProperty("primary", true);
    for (QPushButton* b : {cancelButton_, pauseButton_, startButton_}) actions->addWidget(b);
    what->body()->addLayout(actions);
    col->addWidget(what);

    auto* progressCard = new Card(QStringLiteral("Progresso"), content);
    phase_ = new QLabel(QStringLiteral("Nenhuma varredura em andamento."), progressCard);
    progressCard->body()->addWidget(phase_);
    bar_ = new QProgressBar(progressCard);
    bar_->setRange(0, 1);
    bar_->setValue(0);
    progressCard->body()->addWidget(bar_);
    current_ = mutedLabel(QString(), progressCard);
    current_->setWordWrap(false);
    current_->setTextInteractionFlags(Qt::NoTextInteraction);
    progressCard->body()->addWidget(current_);
    auto* counters = new QHBoxLayout;
    threats_ = new StatusPill(QStringLiteral("Ameaças: 0"), StatusPill::Tone::Neutral, progressCard);
    suspicious_ = new StatusPill(QStringLiteral("Suspeitos ou PUA: 0"), StatusPill::Tone::Neutral, progressCard);
    errors_ = new StatusPill(QStringLiteral("Não analisados: 0"), StatusPill::Tone::Neutral, progressCard);
    for (StatusPill* p : {threats_, suspicious_, errors_}) counters->addWidget(p);
    counters->addStretch();
    progressCard->body()->addLayout(counters);
    col->addWidget(progressCard);

    auto* found = new Card(QStringLiteral("Achados desta varredura"), content);
    findings_ = makeTable({"Risco", "Classificação", "Arquivo", "Categoria", "Local"}, found);
    findings_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    findings_->setTextElideMode(Qt::ElideMiddle);
    findings_->setWordWrap(false);
    found->body()->addWidget(findings_);
    summaryLabel_ = mutedLabel(QString(), found);
    found->body()->addWidget(summaryLabel_);
    auto* resultsRow = new QHBoxLayout;
    resultsRow->addStretch();
    resultsButton_ = new QPushButton(icon(QStringLiteral("file-text")), QStringLiteral("Abrir a análise completa"), found);
    resultsRow->addWidget(resultsButton_);
    found->body()->addLayout(resultsRow);
    col->addWidget(found);
    col->addStretch();
    fitTableToContents(findings_);

    auto* scans = ctx_->scans();
    connect(scans, &gk::bridge::ScanService::started, this, [this](qint64 id) { scanId_ = id; });
    connect(scans, &gk::bridge::ScanService::progressChanged, this, &ScanPage::onProgress);
    connect(scans, &gk::bridge::ScanService::fileAnalyzed, this, &ScanPage::onFile);
    connect(scans, &gk::bridge::ScanService::finished, this, &ScanPage::onFinished);
    connect(addFolder, &QPushButton::clicked, this, [this] {
        const QString dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Escolher a pasta"));
        if (!dir.isEmpty()) addTarget(dir);
    });
    connect(addFile, &QPushButton::clicked, this, [this] {
        const QString file = QFileDialog::getOpenFileName(this, QStringLiteral("Escolher o arquivo"));
        if (!file.isEmpty()) addTarget(file);
    });
    connect(removeButton_, &QPushButton::clicked, this, [this] {
        delete targets_->currentItem();
        updateButtons();
    });
    connect(targets_, &QListWidget::currentRowChanged, this, &ScanPage::updateButtons);
    connect(startButton_, &QPushButton::clicked, this, &ScanPage::start);
    connect(pauseButton_, &QPushButton::clicked, this, [this] { paused_ ? resume() : pause(); });
    connect(cancelButton_, &QPushButton::clicked, this, &ScanPage::cancel);
    connect(resultsButton_, &QPushButton::clicked, this, [this] {
        if (scanId_ > 0) emit openResults(scanId_);
    });
    updateButtons();
}

void ScanPage::addTarget(const QString& path) {
    const QString absolute = QDir::toNativeSeparators(QFileInfo(path).absoluteFilePath());
    if (!targets().contains(absolute)) targets_->addItem(absolute);
    updateButtons();
}

void ScanPage::clearTargets() {
    targets_->clear();
    updateButtons();
}

QStringList ScanPage::targets() const {
    QStringList out;
    for (int i = 0; i < targets_->count(); ++i) out << targets_->item(i)->text();
    return out;
}

void ScanPage::setDeep(bool deep) { (deep ? deep_ : quick_)->setChecked(true); }

bool ScanPage::running() const { return ctx_->scans()->running(); }

int ScanPage::findingsCount() const { return findings_->rowCount(); }

bool ScanPage::start() {
    if (running() || targets().isEmpty()) return false;
    QStringList paths;
    for (const QString& t : targets()) paths << QDir::fromNativeSeparators(t);
    if (!ctx_->scans()->start(paths, deep_->isChecked(), QStringLiteral("Segurança do jogo"))) return false;
    summary_ = {};
    scanId_ = 0;
    paused_ = false;
    findings_->setRowCount(0);
    fitTableToContents(findings_);
    summaryLabel_->clear();
    phase_->setText(phaseLabel(QStringLiteral("enumerating")));
    bar_->setRange(0, 0);   // indeterminate until the files are counted
    updateButtons();
    return true;
}

void ScanPage::pause() {
    if (!running()) return;
    ctx_->scans()->pause();
    paused_ = true;
    updateButtons();
}

void ScanPage::resume() {
    if (!running()) return;
    ctx_->scans()->resume();
    paused_ = false;
    updateButtons();
}

void ScanPage::cancel() {
    if (running()) ctx_->scans()->cancel();
}

void ScanPage::updateButtons() {
    const bool busy = running();
    startButton_->setEnabled(!busy && targets_->count() > 0);
    pauseButton_->setEnabled(busy);
    pauseButton_->setText(paused_ ? QStringLiteral("Retomar") : QStringLiteral("Pausar"));
    pauseButton_->setIcon(icon(paused_ ? QStringLiteral("play") : QStringLiteral("pause")));
    cancelButton_->setEnabled(busy);
    removeButton_->setEnabled(!busy && targets_->currentRow() >= 0);
    deep_->setEnabled(!busy);
    quick_->setEnabled(!busy);
    resultsButton_->setEnabled(!busy && scanId_ > 0 && !summary_.isEmpty());
}

void ScanPage::onProgress(const QJsonObject& p) {
    const qint64 total = p.value("files_total").toInteger();
    const qint64 done = p.value("files_done").toInteger();
    const QString phase = p.value("phase").toString();
    phase_->setText(p.value("paused").toBool() ? QStringLiteral("Pausada.")
                                               : QStringLiteral("%1 %2 de %3 arquivos.").arg(phaseLabel(phase)).arg(done).arg(total));
    if (total > 0 && phase != QLatin1String("enumerating")) {
        bar_->setRange(0, int(std::min<qint64>(total, INT_MAX)));
        bar_->setValue(int(std::min<qint64>(done, INT_MAX)));
    }
    const QString file = QDir::toNativeSeparators(p.value("current").toString());
    current_->setText(fontMetrics().elidedText(file, Qt::ElideMiddle, std::max(200, current_->width())));
    const qint64 threats = p.value("threats").toInteger();
    const qint64 suspicious = p.value("suspicious").toInteger() + p.value("pua").toInteger();
    const qint64 errors = p.value("errors").toInteger() + p.value("skipped").toInteger();
    threats_->set(QStringLiteral("Ameaças: %1").arg(threats), threats > 0 ? StatusPill::Tone::Bad : StatusPill::Tone::Good);
    suspicious_->set(QStringLiteral("Suspeitos ou PUA: %1").arg(suspicious),
                     suspicious > 0 ? StatusPill::Tone::Warning : StatusPill::Tone::Good);
    errors_->set(QStringLiteral("Não analisados: %1").arg(errors),
                 errors > 0 ? StatusPill::Tone::Warning : StatusPill::Tone::Neutral);
}

void ScanPage::onFile(const QJsonObject& r) {
    if (!isFinding(r)) return;
    const auto& catalog = ctx_->catalog();
    const int row = findings_->rowCount();
    findings_->insertRow(row);
    const QString risk = r.value("risk").toString();
    auto* riskItem = new QTableWidgetItem(riskLabel(risk));
    riskItem->setForeground(riskColor(risk));
    const QString where = r.value("container").isString() && !r.value("container").toString().isEmpty()
                              ? QStringLiteral("%1 → %2").arg(QDir::toNativeSeparators(r.value("container").toString()),
                                                              r.value("member_path").toString())
                              : QDir::toNativeSeparators(r.value("path").toString());
    const QStringList texts{catalog.classification(r.value("classification").toString()), r.value("name").toString(),
                            r.value("primary_category").isString() ? catalog.categoryLabel(r.value("primary_category").toString())
                                                                   : QStringLiteral("—"),
                            where};
    findings_->setItem(row, 0, riskItem);
    for (int c = 0; c < texts.size(); ++c) {
        auto* item = new QTableWidgetItem(texts[c]);
        item->setToolTip(texts[c]);
        findings_->setItem(row, c + 1, item);
    }
    fitTableToContents(findings_);
}

void ScanPage::onFinished(const QJsonObject& summary) {
    summary_ = summary;
    if (summary.value("scan_id").toInteger() > 0) scanId_ = summary.value("scan_id").toInteger();
    paused_ = false;
    bar_->setRange(0, 1);
    bar_->setValue(1);
    current_->clear();
    const QString status = summary.value("status").toString();
    const QJsonObject classes = summary.value("counts_by_classification").toObject();
    const int threats = classes.value("malware").toInt();
    const int suspicious = classes.value("suspicious").toInt() + classes.value("pua").toInt();
    QString text;
    AppContext::Level level = AppContext::Level::Success;
    if (status == QLatin1String("failed")) {
        text = QStringLiteral("A varredura falhou: %1").arg(summary.value("error").toString());
        phase_->setText(QStringLiteral("Falhou."));
        level = AppContext::Level::Error;
    } else {
        phase_->setText(status == QLatin1String("cancelled") ? QStringLiteral("Cancelada (os resultados até aqui foram gravados).")
                                                             : phaseLabel(QStringLiteral("done")));
        text = QStringLiteral("%1 arquivos analisados: %2 ameaça(s), %3 suspeito(s) ou PUA.")
                   .arg(summary.value("files_analyzed").toInteger())
                   .arg(threats)
                   .arg(suspicious);
        if (threats > 0) level = AppContext::Level::Error;
        else if (suspicious > 0) level = AppContext::Level::Warning;
        for (const auto& l : summary.value("limitations").toArray()) text += QStringLiteral("\n• ") + l.toString();
    }
    summaryLabel_->setText(text);
    updateButtons();
    emit ctx_->notify(level, QStringLiteral("Varredura"), text.section('\n', 0, 0));
    emit scanFinished(summary);
}

}  // namespace gk::app
