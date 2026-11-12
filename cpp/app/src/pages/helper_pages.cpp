#include "helper_pages.hpp"

#include "../ui_kit.hpp"

#include <QCheckBox>
#include <QDateTime>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QTableWidget>

namespace gk::app {

namespace {

QWidget* scrollingPage(QWidget* page, QVBoxLayout** column) {
    page->setObjectName(QStringLiteral("page"));
    auto* scroll = new QScrollArea(page);
    scroll->setWidgetResizable(true);
    auto* content = new QWidget(scroll);
    content->setObjectName(QStringLiteral("page"));
    *column = new QVBoxLayout(content);
    (*column)->setContentsMargins(0, 0, 8, 0);
    (*column)->setSpacing(16);
    scroll->setWidget(content);
    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->addWidget(scroll);
    return content;
}

QLabel* mutedLabel(const QString& text, QWidget* parent) {
    auto* l = new QLabel(text, parent);
    l->setWordWrap(true);
    l->setProperty("muted", true);
    return l;
}

const char* kSampleFilter = "Executáveis e scripts (*.exe *.dll *.bat *.cmd *.ps1 *.vbs *.js *.msi)";

}  // namespace

// ============================================================================================ sandbox
SandboxPage::SandboxPage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);

    auto* availability = new Card(QStringLiteral("Isolamento"), content);
    auto* row = new QHBoxLayout;
    pill_ = new StatusPill(QStringLiteral("Verificando…"), StatusPill::Tone::Neutral, availability);
    reasonLabel_ = new QLabel(availability);
    reasonLabel_->setWordWrap(true);
    row->addWidget(pill_, 0, Qt::AlignTop);
    row->addWidget(reasonLabel_, 1);
    availability->body()->addLayout(row);
    enable_ = new QCheckBox(QStringLiteral("Ativar a análise comportamental (executa a amostra apenas dentro de uma máquina "
                                           "virtual descartável e sem rede)"),
                            availability);
    enable_->setChecked(ctx_->setting(QStringLiteral("sandbox.enabled"), false).toBool());
    availability->body()->addWidget(enable_);
    col->addWidget(availability);

    auto* sample = new Card(QStringLiteral("Amostra"), content);
    auto* pickRow = new QHBoxLayout;
    sampleLabel_ = new QLabel(QStringLiteral("Nenhum arquivo escolhido."), sample);
    sampleLabel_->setWordWrap(true);
    auto* choose = new QPushButton(icon(QStringLiteral("file")), QStringLiteral("Escolher arquivo…"), sample);
    pickRow->addWidget(sampleLabel_, 1);
    pickRow->addWidget(choose);
    sample->body()->addLayout(pickRow);
    auto* runRow = new QHBoxLayout;
    runRow->addWidget(new QLabel(QStringLiteral("Tempo de observação (s):"), sample));
    timeout_ = new QSpinBox(sample);
    timeout_->setRange(30, 1800);
    timeout_->setButtonSymbols(QAbstractSpinBox::NoButtons);
    timeout_->setToolTip(QStringLiteral("Entre 30 e 1800 segundos."));
    timeout_->setValue(ctx_->setting(QStringLiteral("sandbox.timeout_seconds"), 120).toInt(120));
    runRow->addWidget(timeout_);
    runRow->addStretch();
    analyzeButton_ = new QPushButton(icon(QStringLiteral("play"), Qt::white), QStringLiteral("Analisar na máquina virtual"), sample);
    analyzeButton_->setProperty("primary", true);
    cancelButton_ = new QPushButton(icon(QStringLiteral("stop")), QStringLiteral("Cancelar"), sample);
    runRow->addWidget(analyzeButton_);
    runRow->addWidget(cancelButton_);
    sample->body()->addLayout(runRow);
    progress_ = new QProgressBar(sample);
    progress_->setRange(0, 0);
    progress_->setVisible(false);
    sample->body()->addWidget(progress_);
    status_ = mutedLabel(QString(), sample);
    sample->body()->addWidget(status_);
    col->addWidget(sample);

    auto* results = new Card(QStringLiteral("Comportamento observado"), content);
    evidences_ = makeTable({"Severidade", "Evidência", "Categoria", "Detalhes"}, results);
    results->body()->addWidget(evidences_);
    limitations_ = mutedLabel(QString(), results);
    results->body()->addWidget(limitations_);
    col->addWidget(results);
    col->addStretch();

    auto* helper = ctx_->helper();
    connect(helper, &gk::ipc::HelperClient::callSucceeded, this, &SandboxPage::onSucceeded);
    connect(helper, &gk::ipc::HelperClient::callFailed, this, &SandboxPage::onFailed);
    connect(helper, &gk::ipc::HelperClient::eventReceived, this, &SandboxPage::onEvent);
    connect(choose, &QPushButton::clicked, this, [this] {
        const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Escolher amostra"), QString(),
                                                          QString::fromUtf8(kSampleFilter));
        if (!path.isEmpty()) setSample(path);
    });
    connect(enable_, &QCheckBox::toggled, this, [this](bool on) {
        QString error;
        if (!ctx_->setSetting(QStringLiteral("sandbox.enabled"), on, &error))
            emit ctx_->notify(AppContext::Level::Error, QStringLiteral("Configurações"), error);
        updateButtons();
    });
    connect(timeout_, &QSpinBox::valueChanged, this, [this](int v) { ctx_->setSetting(QStringLiteral("sandbox.timeout_seconds"), v); });
    connect(analyzeButton_, &QPushButton::clicked, this, &SandboxPage::analyze);
    connect(cancelButton_, &QPushButton::clicked, this, &SandboxPage::cancel);
    updateButtons();
    checkAvailability();
}

bool SandboxPage::canAnalyze() const {
    return available_ && enable_->isChecked() && !sample_.isEmpty() && analyzeCall_ < 0;
}

void SandboxPage::updateButtons() {
    analyzeButton_->setEnabled(canAnalyze());
    cancelButton_->setEnabled(analyzeCall_ >= 0);
    QString why;
    if (!available_) why = QStringLiteral("Isolamento indisponível: nada será executado.");
    else if (!enable_->isChecked()) why = QStringLiteral("Ative a análise comportamental acima.");
    else if (sample_.isEmpty()) why = QStringLiteral("Escolha um arquivo.");
    analyzeButton_->setToolTip(why);
}

void SandboxPage::checkAvailability() {
    pill_->set(QStringLiteral("Verificando…"), StatusPill::Tone::Neutral);
    availabilityCall_ = ctx_->helper()->call(QStringLiteral("sandbox.availability"), {}, 30000);
}

void SandboxPage::setSample(const QString& path) {
    sample_ = path;
    const QFileInfo fi(path);
    sampleLabel_->setText(QStringLiteral("%1\n%2 KB — %3").arg(fi.fileName()).arg(fi.size() / 1024).arg(fi.absolutePath()));
    updateButtons();
}

void SandboxPage::analyze() {
    if (!canAnalyze()) return;
    const QString text = QStringLiteral(
        "O arquivo será copiado para uma máquina virtual descartável do Windows Sandbox, sem rede, e executado "
        "lá dentro por %1 segundos. Ele não é executado neste computador.\n\nLimitações: malwares podem detectar a "
        "máquina virtual e não agir; a ausência de comportamento suspeito não garante segurança.\n\nIniciar a análise de %2?")
        .arg(timeout_->value()).arg(QFileInfo(sample_).fileName());
    if (!ctx_->ask(this, QStringLiteral("Análise comportamental"), text)) return;
    evidences_->setRowCount(0);
    progress_->setVisible(true);
    status_->setText(QStringLiteral("Iniciando a máquina virtual…"));
    const int timeoutMs = (timeout_->value() + 240) * 1000;
    analyzeCall_ = ctx_->helper()->call(QStringLiteral("sandbox.analyze"),
                                        {{"path", sample_}, {"timeout_seconds", timeout_->value()}}, timeoutMs);
    updateButtons();
}

void SandboxPage::cancel() {
    if (analyzeCall_ >= 0) ctx_->helper()->cancel(analyzeCall_);
    status_->setText(QStringLiteral("Cancelando e descartando a máquina virtual…"));
}

void SandboxPage::onEvent(qint64 id, const QString& name, const QJsonObject& data) {
    if (id != analyzeCall_ || name != QLatin1String("progress")) return;
    const QString stage = data.value("stage").toString();
    if (stage == "boot") status_->setText(QStringLiteral("Iniciando a máquina virtual sem rede…"));
    else if (stage == "running") status_->setText(QStringLiteral("Observando a amostra (%1 s)…").arg(data.value("elapsed").toInt()));
    else if (stage == "collecting") status_->setText(QStringLiteral("Coletando observações e descartando a máquina virtual…"));
}

void SandboxPage::onSucceeded(qint64 id, const QJsonValue& result) {
    const QJsonObject r = result.toObject();
    if (id == availabilityCall_) {
        availabilityCall_ = -1;
        available_ = r.value("available").toBool();
        reason_ = r.value("reason").toString();
        pill_->set(available_ ? QStringLiteral("Disponível") : QStringLiteral("Indisponível"),
                   available_ ? StatusPill::Tone::Good : StatusPill::Tone::Warning);
        reasonLabel_->setText(reason_);
        QStringList lims;
        for (const auto& l : r.value("limitations").toArray()) lims << QStringLiteral("• ") + l.toString();
        limitations_->setText(lims.join('\n'));
        updateButtons();
        emit availabilityChecked(available_);
    } else if (id == analyzeCall_) {
        analyzeCall_ = -1;
        progress_->setVisible(false);
        showReport(r);
        updateButtons();
        const bool ok = r.value("error").isNull() || r.value("error").toString().isEmpty();
        emit analysisFinished(ok, ok ? QString() : r.value("error").toString());
    }
}

void SandboxPage::onFailed(qint64 id, const gk::ipc::CallError& error) {
    if (id == availabilityCall_) {
        availabilityCall_ = -1;
        available_ = false;
        reason_ = QStringLiteral("Processo auxiliar indisponível: %1").arg(error.message);
        pill_->set(QStringLiteral("Indisponível"), StatusPill::Tone::Bad);
        reasonLabel_->setText(reason_);
        updateButtons();
        emit availabilityChecked(false);
    } else if (id == analyzeCall_) {
        analyzeCall_ = -1;
        progress_->setVisible(false);
        status_->setText(error.message);
        updateButtons();
        emit ctx_->notify(AppContext::Level::Error, QStringLiteral("Análise comportamental"), error.message);
        emit analysisFinished(false, error.message);
    }
}

void SandboxPage::showReport(const QJsonObject& report) {
    const QJsonArray evs = report.value("evidences").toArray();
    evidences_->setRowCount(0);
    for (const auto& v : evs) {
        const QJsonObject e = v.toObject();
        const int row = evidences_->rowCount();
        evidences_->insertRow(row);
        auto* sev = new QTableWidgetItem(riskLabel(e.value("severity").toString()));
        sev->setForeground(riskColor(e.value("severity").toString()));
        evidences_->setItem(row, 0, sev);
        evidences_->setItem(row, 1, new QTableWidgetItem(e.value("title").toString()));
        evidences_->setItem(row, 2, new QTableWidgetItem(e.value("category").toString()));
        QStringList details{e.value("description").toString()};
        for (const auto& l : e.value("locations").toArray()) {
            const QJsonObject loc = l.toObject();
            details << QStringLiteral("%1: %2").arg(loc.value("description").toString(), loc.value("excerpt").toString());
        }
        if (!e.value("fp_note").toString().isEmpty()) details << QStringLiteral("Falso positivo possível: ") + e.value("fp_note").toString();
        evidences_->setItem(row, 3, new QTableWidgetItem(details.join('\n')));
    }
    fitTableToContents(evidences_, 12);
    const QString error = report.value("error").toString();
    status_->setText(error.isEmpty() ? QStringLiteral("Análise concluída: %1 evidência(s). Relatório salvo em %2.")
                                           .arg(evs.size()).arg(report.value("report_path").toString())
                                     : error);
    QStringList lims;
    for (const auto& l : report.value("limitations").toArray()) lims << QStringLiteral("• ") + l.toString();
    limitations_->setText(lims.join('\n'));
    emit ctx_->notify(error.isEmpty() ? AppContext::Level::Success : AppContext::Level::Warning,
                      QStringLiteral("Análise comportamental"), status_->text());
}

// ============================================================================================ privacy
PrivacyPage::PrivacyPage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);

    auto* helperCard = new Card(QStringLiteral("Processo auxiliar Python"), content);
    auto* hRow = new QHBoxLayout;
    helperPill_ = new StatusPill(QStringLiteral("Verificando…"), StatusPill::Tone::Neutral, helperCard);
    helperDetails_ = new QLabel(helperCard);
    helperDetails_->setWordWrap(true);
    hRow->addWidget(helperPill_, 0, Qt::AlignTop);
    hRow->addWidget(helperDetails_, 1);
    helperCard->body()->addLayout(hRow);
    auto* hButtons = new QHBoxLayout;
    auto* check = new QPushButton(icon(QStringLiteral("refresh")), QStringLiteral("Verificar"), helperCard);
    auto* restart = new QPushButton(icon(QStringLiteral("rotate-ccw")), QStringLiteral("Reiniciar processo auxiliar"), helperCard);
    hButtons->addWidget(check);
    hButtons->addWidget(restart);
    hButtons->addStretch();
    helperCard->body()->addLayout(hButtons);
    col->addWidget(helperCard);

    auto* netCard = new Card(QStringLiteral("Autoteste de rede"), content);
    netCard->body()->addWidget(mutedLabel(
        QStringLiteral("Tenta resolver um nome na internet e abrir uma conexão a partir do processo auxiliar e confirma que "
                       "ambos são bloqueados. O aplicativo em C++ não usa bibliotecas de rede, e o canal com o auxiliar usa "
                       "pipes anônimos, não conexões."),
        netCard));
    auto* nRow = new QHBoxLayout;
    netPill_ = new StatusPill(QStringLiteral("Não executado"), StatusPill::Tone::Neutral, netCard);
    netDetails_ = new QLabel(netCard);
    netDetails_->setWordWrap(true);
    nRow->addWidget(netPill_, 0, Qt::AlignTop);
    nRow->addWidget(netDetails_, 1);
    netCard->body()->addLayout(nRow);
    auto* run = new QPushButton(icon(QStringLiteral("wifi-off"), Qt::white), QStringLiteral("Executar autoteste"), netCard);
    run->setProperty("primary", true);
    auto* runRow = new QHBoxLayout;
    runRow->addWidget(run);
    runRow->addStretch();
    netCard->body()->addLayout(runRow);
    attempts_ = makeTable({"Hora", "Tentativa bloqueada", "Destino", "Origem"}, netCard);
    netCard->body()->addWidget(attempts_);
    col->addWidget(netCard);

    auto* policy = new Card(QStringLiteral("Política de privacidade"), content);
    policy->body()->addWidget(mutedLabel(
        QStringLiteral("• Nada sai do computador: sem telemetria, anúncios, rastreamento, conta ou consulta online.\n"
                       "• Atualizações só por pacotes .gkpkg locais e assinados.\n"
                       "• Resultados, histórico, quarentena e logs ficam apenas em %1.\n"
                       "• Relatórios omitem o nome de usuário e o nome do computador, a menos que você ative a inclusão.\n"
                       "• Nenhum arquivo analisado é executado fora de uma máquina virtual descartável e sem rede.")
            .arg(ctx_->dataDir()),
        policy));
    col->addWidget(policy);
    col->addStretch();

    auto* helper = ctx_->helper();
    connect(helper, &gk::ipc::HelperClient::callSucceeded, this, &PrivacyPage::onSucceeded);
    connect(helper, &gk::ipc::HelperClient::callFailed, this, &PrivacyPage::onFailed);
    connect(check, &QPushButton::clicked, this, &PrivacyPage::checkHelper);
    connect(restart, &QPushButton::clicked, this, &PrivacyPage::restartHelper);
    connect(run, &QPushButton::clicked, this, &PrivacyPage::runNetworkSelfTest);
    checkHelper();
}

void PrivacyPage::checkHelper() {
    helperPill_->set(QStringLiteral("Verificando…"), StatusPill::Tone::Neutral);
    infoCall_ = ctx_->helper()->call(QStringLiteral("system.info"), {}, 30000);
}

void PrivacyPage::restartHelper() {
    ctx_->helper()->stop();
    ctx_->helper()->resetFailures();
    checkHelper();
}

void PrivacyPage::runNetworkSelfTest() {
    netPill_->set(QStringLiteral("Executando…"), StatusPill::Tone::Neutral);
    selfTestCall_ = ctx_->helper()->call(QStringLiteral("system.network_selftest"), {}, 30000);
}

void PrivacyPage::onSucceeded(qint64 id, const QJsonValue& result) {
    const QJsonObject r = result.toObject();
    if (id == infoCall_) {
        infoCall_ = -1;
        const bool guard = r.value("netguard").toBool();
        helperPill_->set(guard ? QStringLiteral("Ativo e offline") : QStringLiteral("Sem bloqueio de rede"),
                         guard ? StatusPill::Tone::Good : StatusPill::Tone::Bad);
        helperDetails_->setText(QStringLiteral("Versão %1 · protocolo %2 · Python %3 · %4\nBloqueio de rede (netguard): %5 · "
                                               "tentativas bloqueadas nesta sessão: %6")
                                    .arg(r.value("version").toString())
                                    .arg(r.value("protocol").toInt())
                                    .arg(r.value("python").toString(),
                                         r.value("frozen").toBool() ? QStringLiteral("empacotado") : QStringLiteral("desenvolvimento"),
                                         guard ? QStringLiteral("ativo") : QStringLiteral("INATIVO"))
                                    .arg(r.value("network_blocked_attempts").toInt()));
        emit helperChecked(guard);
    } else if (id == selfTestCall_) {
        selfTestCall_ = -1;
        const bool ok = r.value("ok").toBool();
        verdict_ = ok ? QStringLiteral("ok") : QStringLiteral("falha");
        netPill_->set(ok ? QStringLiteral("Offline confirmado") : QStringLiteral("FALHA"),
                      ok ? StatusPill::Tone::Good : StatusPill::Tone::Bad);
        netDetails_->setText(QStringLiteral("Resolução de nomes (DNS): %1\nConexão de saída: %2")
                                 .arg(r.value("dns").toString(), r.value("connect").toString()));
        attempts_->setRowCount(0);
        for (const auto& v : r.value("blocked_attempts").toArray()) {
            const QJsonObject a = v.toObject();
            const int row = attempts_->rowCount();
            attempts_->insertRow(row);
            const QString when = QDateTime::fromSecsSinceEpoch(qint64(a.value("timestamp").toDouble())).toString(QStringLiteral("HH:mm:ss"));
            const QStringList cells{when, a.value("event").toString(), a.value("target").toString(), a.value("origin").toString()};
            for (int c = 0; c < cells.size(); ++c) attempts_->setItem(row, c, new QTableWidgetItem(cells[c]));
        }
        fitTableToContents(attempts_);
        checkHelper();   // refresh the blocked-attempt counter
        emit ctx_->notify(ok ? AppContext::Level::Success : AppContext::Level::Error, QStringLiteral("Autoteste de rede"),
                          ok ? QStringLiteral("DNS e conexões de saída estão bloqueados no processo auxiliar.")
                             : QStringLiteral("O bloqueio de rede não funcionou como esperado."));
        emit selfTestFinished(ok);
    }
}

void PrivacyPage::onFailed(qint64 id, const gk::ipc::CallError& error) {
    if (id == infoCall_) {
        infoCall_ = -1;
        helperPill_->set(QStringLiteral("Indisponível"), StatusPill::Tone::Bad);
        helperDetails_->setText(error.message);
        emit helperChecked(false);
    } else if (id == selfTestCall_) {
        selfTestCall_ = -1;
        verdict_ = QStringLiteral("falha");
        netPill_->set(QStringLiteral("Não executado"), StatusPill::Tone::Bad);
        netDetails_->setText(error.message);
        emit selfTestFinished(false);
    }
}

}  // namespace gk::app
