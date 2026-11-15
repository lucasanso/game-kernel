#include "realtime_page.hpp"

#include "../ui_kit.hpp"
#include "scan_table.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonObject>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTableWidget>

#include <algorithm>

namespace gk::app {

namespace {

const QStringList kLevels{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};

QTableWidgetItem* cell(const QString& text) {
    auto* item = new QTableWidgetItem(text);
    item->setToolTip(text);
    return item;
}

QString eventLabel(const QString& event, const QJsonObject& detail) {
    if (event == QLatin1String("detected")) {
        const QString action = detail.value("action").toString();
        if (action == QLatin1String("quarantined")) return QStringLiteral("Encontrado e isolado");
        if (action == QLatin1String("restored_before")) return QStringLiteral("Encontrado (restaurado por você)");
        return QStringLiteral("Encontrado");
    }
    if (event == QLatin1String("quarantined")) return QStringLiteral("Quarentena automática");
    if (event == QLatin1String("quarantine_failed")) return QStringLiteral("Quarentena falhou");
    if (event == QLatin1String("overflow")) return QStringLiteral("Pasta verificada de novo");
    if (event == QLatin1String("error")) return QStringLiteral("Erro");
    return event;
}

bool underFolder(const QString& path, const QString& folder) {
#ifdef _WIN32
    const Qt::CaseSensitivity cs = Qt::CaseInsensitive;
#else
    const Qt::CaseSensitivity cs = Qt::CaseSensitive;
#endif
    const QString p = QDir::cleanPath(QFileInfo(path).absoluteFilePath());
    const QString f = QDir::cleanPath(QFileInfo(folder).absoluteFilePath());
    return p.compare(f, cs) == 0 || p.startsWith(f.endsWith(QLatin1Char('/')) ? f : f + QLatin1Char('/'), cs);
}

}  // namespace

RealtimePage::RealtimePage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);

    auto* mainCard = new Card(QStringLiteral("Proteção em tempo real"), content);
    mainCard->body()->addWidget(mutedLabel(
        QStringLiteral("Observa as pastas que você escolher (jogos, downloads, mods) e analisa cada arquivo novo ou "
                       "alterado assim que ele termina de ser gravado, no modo rápido e com o mesmo motor da varredura. "
                       "Nada é executado e nada sai deste computador.\n\nLimites: ela não impede que um programa seja "
                       "aberto antes de a análise terminar (isso exigiria um driver do sistema) e funciona enquanto o "
                       "Game Kernel estiver aberto — ao fechar a janela com a proteção ativa, ele continua na área de "
                       "notificação."),
        mainCard));
    auto* head = new QHBoxLayout;
    pill_ = new StatusPill(QStringLiteral("…"), StatusPill::Tone::Neutral, mainCard);
    head->addWidget(pill_);
    head->addStretch();
    toggle_ = new QPushButton(mainCard);
    toggle_->setProperty("primary", true);
    head->addWidget(toggle_);
    mainCard->body()->addLayout(head);
    summary_ = mutedLabel(QString(), mainCard);
    mainCard->body()->addWidget(summary_);
    col->addWidget(mainCard);

    auto* foldersCard = new Card(QStringLiteral("Pastas observadas"), content);
    foldersCard->body()->addWidget(mutedLabel(QStringLiteral("Subpastas também são observadas. A pasta de dados do Game Kernel "
                                                             "(banco, quarentena) e as exclusões da varredura ficam de fora."),
                                              foldersCard));
    folderList_ = new QListWidget(foldersCard);
    folderList_->setMinimumHeight(90);
    folderList_->setMaximumHeight(150);
    foldersCard->body()->addWidget(folderList_);
    auto* folderRow = new QHBoxLayout;
    addFolder_ = new QPushButton(icon(QStringLiteral("plus")), QStringLiteral("Adicionar pasta…"), foldersCard);
    removeFolder_ = new QPushButton(icon(QStringLiteral("minus")), QStringLiteral("Remover"), foldersCard);
    folderRow->addWidget(addFolder_);
    folderRow->addWidget(removeFolder_);
    folderRow->addStretch();
    foldersCard->body()->addLayout(folderRow);
    col->addWidget(foldersCard);

    auto* actCard = new Card(QStringLiteral("Quando algo for encontrado"), content);
    auto* form = new QFormLayout;
    notifyLevel_ = new QComboBox(actCard);
    for (const QString& level : kLevels) notifyLevel_->addItem(riskLabel(level), level);
    form->addRow(QStringLiteral("Avisar a partir do risco"), notifyLevel_);
    batch_ = new QSpinBox(actCard);
    batch_->setRange(2, 300);
    batch_->setSuffix(QStringLiteral(" s"));
    form->addRow(QStringLiteral("Juntar alterações por"), batch_);
    stable_ = new QSpinBox(actCard);
    stable_->setRange(1, 60);
    stable_->setSuffix(QStringLiteral(" s"));
    form->addRow(QStringLiteral("Esperar o arquivo parar de mudar por"), stable_);
    actCard->body()->addLayout(form);
    autoQuarantine_ = new QCheckBox(QStringLiteral("Colocar em quarentena automaticamente as ameaças confirmadas por assinatura"), actCard);
    actCard->body()->addWidget(autoQuarantine_);
    actCard->body()->addWidget(mutedLabel(QStringLiteral("Só ameaças identificadas com certeza (assinatura, regra YARA de família ou "
                                                         "indicador local) são isoladas; suspeitas por heurística apenas avisam. "
                                                         "Um arquivo que você restaurar da quarentena não é isolado de novo."),
                                          actCard));
    col->addWidget(actCard);

    auto* eventsCard = new Card(QStringLiteral("Eventos recentes"), content);
    table_ = makeTable({"Quando", "Arquivo", "Evento", "Risco", "Classificação", "Detalhe"}, eventsCard);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    table_->setTextElideMode(Qt::ElideMiddle);
    table_->setWordWrap(false);
    eventsCard->body()->addWidget(table_);
    empty_ = mutedLabel(QStringLiteral("Nenhum evento registrado ainda."), eventsCard);
    eventsCard->body()->addWidget(empty_);
    auto* eventsRow = new QHBoxLayout;
    auto* refresh = new QPushButton(icon(QStringLiteral("refresh")), QStringLiteral("Atualizar"), eventsCard);
    openScan_ = new QPushButton(icon(QStringLiteral("file-search")), QStringLiteral("Ver análise"), eventsCard);
    eventsRow->addWidget(refresh);
    eventsRow->addStretch();
    eventsRow->addWidget(openScan_);
    eventsCard->body()->addLayout(eventsRow);
    col->addWidget(eventsCard);
    col->addStretch();

    auto* rt = ctx_->realtime();
    connect(rt, &gk::bridge::RealtimeService::statusChanged, this, &RealtimePage::showStatus);
    connect(rt, &gk::bridge::RealtimeService::eventRecorded, this, [this] { refreshEvents(); });
    connect(rt, &gk::bridge::RealtimeService::eventsListed, this, [this](qint64 request, const QJsonArray& events) {
        if (request != eventsRequest_) return;
        eventsRequest_ = -1;
        showEvents(events);
        if (eventsDirty_) {
            eventsDirty_ = false;
            refreshEvents();
        }
    });
    connect(rt, &gk::bridge::RealtimeService::failed, this, [this](qint64 request, const QString& message) {
        if (request != eventsRequest_) return;
        eventsRequest_ = -1;
        error_ = message;
        empty_->setText(QStringLiteral("Não foi possível ler os eventos: %1").arg(message));
        empty_->setVisible(true);
    });
    connect(toggle_, &QPushButton::clicked, this, [this] { setProtectionEnabled(!status_.value("enabled").toBool()); });
    connect(addFolder_, &QPushButton::clicked, this, [this] {
        const QString dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Pasta para observar"));
        if (!dir.isEmpty()) addFolder(dir);
    });
    connect(removeFolder_, &QPushButton::clicked, this, [this] {
        if (auto* item = folderList_->currentItem()) removeFolder(item->data(Qt::UserRole).toString());
    });
    connect(folderList_, &QListWidget::currentRowChanged, this, [this](int row) { removeFolder_->setEnabled(row >= 0); });
    connect(notifyLevel_, &QComboBox::currentIndexChanged, this, [this](int i) { setNotifyMinRisk(notifyLevel_->itemData(i).toString()); });
    connect(batch_, &QSpinBox::editingFinished, this, [this] { setBatchSeconds(batch_->value()); });
    connect(stable_, &QSpinBox::editingFinished, this, [this] { setStableSeconds(stable_->value()); });
    connect(autoQuarantine_, &QCheckBox::toggled, this, [this](bool on) {
        if (!setAutoQuarantine(on)) reload();
    });
    connect(refresh, &QPushButton::clicked, this, &RealtimePage::refreshEvents);
    connect(openScan_, &QPushButton::clicked, this, &RealtimePage::openSelectedEvent);
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this] {
        const auto rows = table_->selectionModel()->selectedRows();
        openScan_->setEnabled(!rows.isEmpty() && events_.at(rows.first().row()).toObject().value("scan_id").toInteger() > 0);
    });
    connect(ctx_, &AppContext::settingChanged, this, [this](const QString& key) {
        if (key.startsWith(QLatin1String("realtime."))) reload();
    });
    reload();
    showStatus(rt->status());
    refreshEvents();
}

bool RealtimePage::write(const QString& key, const QJsonValue& value) {
    QString error;
    if (!ctx_->setSetting(key, value, &error)) {
        error_ = QStringLiteral("Não foi possível gravar as configurações: %1").arg(error);
        emit ctx_->notify(AppContext::Level::Error, QStringLiteral("Proteção em tempo real"), error_);
        reload();
        return false;
    }
    error_.clear();
    return true;
}

void RealtimePage::reload() {
    const gk::realtime::Settings s = ctx_->realtimeSettings();
    const QSignalBlocker b1(notifyLevel_), b2(autoQuarantine_), b3(batch_), b4(stable_);
    const QString previous = folderList_->currentItem() ? folderList_->currentItem()->data(Qt::UserRole).toString() : QString();
    folderList_->clear();
    for (const QString& f : s.folders) {
        auto* item = new QListWidgetItem(icon(QStringLiteral("folder")), QDir::toNativeSeparators(f), folderList_);
        item->setData(Qt::UserRole, f);
        if (f == previous) folderList_->setCurrentItem(item);
    }
    notifyLevel_->setCurrentIndex(std::clamp(s.notifyMinRisk - 1, 0, 4));
    autoQuarantine_->setChecked(s.autoQuarantine);
    batch_->setValue(s.batchSeconds);
    stable_->setValue(s.stableSeconds);
    removeFolder_->setEnabled(folderList_->currentRow() >= 0);
    showStatus(status_.isEmpty() ? ctx_->realtime()->status() : status_);
}

bool RealtimePage::setProtectionEnabled(bool on) {
    if (on && ctx_->realtimeSettings().folders.isEmpty()) {
        error_ = QStringLiteral("Adicione pelo menos uma pasta para observar.");
        emit ctx_->notify(AppContext::Level::Warning, QStringLiteral("Proteção em tempo real"), error_);
        return false;
    }
    if (on && !gk::bridge::RealtimeService::supported()) {
        error_ = QStringLiteral("A proteção em tempo real não é suportada neste sistema.");
        emit ctx_->notify(AppContext::Level::Error, QStringLiteral("Proteção em tempo real"), error_);
        return false;
    }
    return write(QStringLiteral("realtime.enabled"), on);
}

bool RealtimePage::addFolder(const QString& folder) {
    const QFileInfo info(folder);
    if (folder.trimmed().isEmpty() || !info.isDir()) {
        error_ = QStringLiteral("A pasta não existe: %1").arg(QDir::toNativeSeparators(folder));
        return false;
    }
    if (underFolder(folder, ctx_->dataDir())) {
        error_ = QStringLiteral("A pasta de dados do Game Kernel não pode ser observada.");
        emit ctx_->notify(AppContext::Level::Warning, QStringLiteral("Proteção em tempo real"), error_);
        return false;
    }
    const QString clean = QDir::cleanPath(info.absoluteFilePath());
    QJsonArray list;
    for (const QString& f : ctx_->realtimeSettings().folders) {
        if (QDir::cleanPath(QFileInfo(f).absoluteFilePath()) == clean) {
            error_ = QStringLiteral("Essa pasta já está na lista.");
            return false;
        }
        list.append(f);
    }
    list.append(clean);
    return write(QStringLiteral("realtime.folders"), list);
}

bool RealtimePage::removeFolder(const QString& folder) {
    QJsonArray list;
    bool found = false;
    for (const QString& f : ctx_->realtimeSettings().folders) {
        if (f == folder) found = true;
        else list.append(f);
    }
    if (!found) return false;
    if (!write(QStringLiteral("realtime.folders"), list)) return false;
    // Without folders there is nothing to protect: the switch follows, so the state shown stays truthful.
    if (list.isEmpty() && ctx_->realtimeSettings().enabled) return write(QStringLiteral("realtime.enabled"), false);
    return true;
}

bool RealtimePage::setNotifyMinRisk(const QString& level) {
    if (!kLevels.contains(level)) return false;
    return write(QStringLiteral("realtime.notify_min_risk"), level);
}

bool RealtimePage::setAutoQuarantine(bool on) {
    if (on && !ctx_->ask(this, QStringLiteral("Quarentena automática"),
                         QStringLiteral("Ameaças confirmadas por assinatura encontradas nas pastas observadas serão movidas para "
                                        "a quarentena sem perguntar (por exemplo, um trainer ou crack com malware conhecido). "
                                        "Você pode restaurá-las depois pela página Quarentena.\n\nAtivar?")))
        return false;
    return write(QStringLiteral("realtime.auto_quarantine"), on);
}

bool RealtimePage::setBatchSeconds(int seconds) {
    if (seconds < 2 || seconds > 300) return false;
    return write(QStringLiteral("realtime.batch_seconds"), seconds);
}

bool RealtimePage::setStableSeconds(int seconds) {
    if (seconds < 1 || seconds > 60) return false;
    return write(QStringLiteral("realtime.stable_seconds"), seconds);
}

void RealtimePage::showStatus(const QJsonObject& status) {
    status_ = status;
    const bool enabled = status.value("enabled").toBool();
    const bool active = status.value("active").toBool();
    const QJsonArray folderStates = status.value("folders").toArray();
    int watching = 0, problems = 0;
    for (const auto& v : folderStates) (v.toObject().value("watching").toBool() ? watching : problems)++;
    if (!status.value("supported").toBool(true)) {
        pill_->set(QStringLiteral("Indisponível"), StatusPill::Tone::Bad);
    } else if (!enabled) {
        pill_->set(QStringLiteral("Desativada"), StatusPill::Tone::Neutral);
    } else if (!active) {
        pill_->set(QStringLiteral("Nenhuma pasta observada"), StatusPill::Tone::Bad);
    } else if (problems > 0) {
        pill_->set(QStringLiteral("Ativa, com avisos"), StatusPill::Tone::Warning);
    } else {
        pill_->set(QStringLiteral("Ativa"), StatusPill::Tone::Good);
    }
    toggle_->setText(enabled ? QStringLiteral("Desativar") : QStringLiteral("Ativar proteção"));
    toggle_->setIcon(icon(enabled ? QStringLiteral("pause") : QStringLiteral("play"), Qt::white));

    QString text;
    if (!enabled) {
        text = ctx_->realtimeSettings().folders.isEmpty() ? QStringLiteral("Adicione as pastas dos seus jogos e downloads e ative a proteção.")
                                                          : QStringLiteral("Ative para analisar automaticamente o que mudar nas pastas abaixo.");
    } else {
        text = QStringLiteral("%1 pasta(s) observada(s). Desde que o programa abriu: %2 arquivo(s) analisado(s) em %3 lote(s), "
                              "%4 achado(s), %5 isolado(s) automaticamente.")
                   .arg(watching)
                   .arg(status.value("files_scanned").toInteger())
                   .arg(status.value("batches").toInteger())
                   .arg(status.value("detections").toInteger())
                   .arg(status.value("quarantined").toInteger());
        if (status.value("scanning").toBool()) text += QStringLiteral("\nAnalisando um lote agora…");
        else if (const qint64 pending = status.value("pending").toInteger(); pending > 0)
            text += QStringLiteral("\n%1 alteração(ões) aguardando o arquivo terminar de ser gravado.").arg(pending);
    }
    summary_->setText(text);

    // Each folder with its real state.
    QHash<QString, QJsonObject> byPath;
    for (const auto& v : folderStates) byPath.insert(v.toObject().value("path").toString(), v.toObject());
    for (int row = 0; row < folderList_->count(); ++row) {
        QListWidgetItem* item = folderList_->item(row);
        const QString f = item->data(Qt::UserRole).toString();
        const QJsonObject st = byPath.value(QDir::cleanPath(QDir::fromNativeSeparators(QFileInfo(f).absoluteFilePath())));
        QString line = QDir::toNativeSeparators(f);
        if (!enabled) line += QStringLiteral(" — proteção desativada");
        else if (st.value("watching").toBool()) line += QStringLiteral(" — observada");
        else if (!st.isEmpty()) line += QStringLiteral(" — NÃO observada: %1").arg(st.value("error").toString());
        item->setText(line);
        item->setForeground(enabled && !st.isEmpty() && !st.value("watching").toBool() ? riskColor(QStringLiteral("HIGH")) : palette().text().color());
    }
    emit statusShown(status);
}

void RealtimePage::refreshEvents() {
    if (eventsRequest_ >= 0) {
        eventsDirty_ = true;   // a burst of events: read once more when this read ends
        return;
    }
    eventsRequest_ = ctx_->realtime()->listEvents(300);
}

void RealtimePage::showEvents(const QJsonArray& events) {
    events_ = events;
    error_.clear();
    table_->setRowCount(0);
    for (const auto& v : events) {
        const QJsonObject e = v.toObject();
        const QJsonObject detail = e.value("detail").toObject();
        const int row = table_->rowCount();
        table_->insertRow(row);
        const QString level = e.value("risk_level").toString();
        auto* risk = cell(e.value("risk").toInt() > 0 ? riskLabel(level) : QStringLiteral("—"));
        if (e.value("risk").toInt() > 0) risk->setForeground(riskColor(level));
        const QString cls = e.value("classification").toString();
        QString what = detail.value("detection").toString();
        const QString message = detail.value("message").toString();
        if (what.isEmpty()) what = message;
        else if (!message.isEmpty()) what += QStringLiteral(" — ") + message;
        table_->setItem(row, 0, cell(scanWhen(e.value("at"))));
        table_->setItem(row, 1, cell(QDir::toNativeSeparators(e.value("path").toString())));
        table_->setItem(row, 2, cell(eventLabel(e.value("event").toString(), detail)));
        table_->setItem(row, 3, risk);
        table_->setItem(row, 4, cell(cls.isEmpty() ? QStringLiteral("—") : ctx_->catalog().classification(cls)));
        table_->setItem(row, 5, cell(what));
    }
    fitTableToContents(table_, 12);
    table_->setVisible(!events.isEmpty());
    empty_->setText(QStringLiteral("Nenhum evento registrado ainda."));
    empty_->setVisible(events.isEmpty());
    if (table_->rowCount() > 0 && table_->selectionModel()->selectedRows().isEmpty()) table_->selectRow(0);
    openScan_->setEnabled(!events.isEmpty() && !table_->selectionModel()->selectedRows().isEmpty() &&
                          events_.at(table_->selectionModel()->selectedRows().first().row()).toObject().value("scan_id").toInteger() > 0);
    emit eventsLoaded(table_->rowCount());
}

bool RealtimePage::openSelectedEvent() {
    const auto rows = table_->selectionModel()->selectedRows();
    if (rows.isEmpty()) return false;
    const qint64 scanId = events_.at(rows.first().row()).toObject().value("scan_id").toInteger();
    if (scanId <= 0) return false;
    emit openResults(scanId);
    return true;
}

QString RealtimePage::statusText() const { return pill_->text() + QStringLiteral(" — ") + summary_->text(); }

QStringList RealtimePage::folders() const { return ctx_->realtimeSettings().folders; }

QString RealtimePage::folderState(int row) const {
    return row >= 0 && row < folderList_->count() ? folderList_->item(row)->text() : QString();
}

int RealtimePage::eventCount() const { return table_->rowCount(); }

}  // namespace gk::app
