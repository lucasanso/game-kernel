#include "updates_page.hpp"

#include "../ui_kit.hpp"

#include <QDate>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QTableWidget>
#include <QtConcurrent>

namespace gk::app {

namespace {

void setRow(QTableWidget* t, int row, const QStringList& values) {
    for (int c = 0; c < values.size(); ++c) t->setItem(row, c, new QTableWidgetItem(values[c]));
}

QString formatIso(const QString& iso) {
    const QDateTime dt = QDateTime::fromString(iso, Qt::ISODate);
    return dt.isValid() ? QLocale(QLocale::Portuguese, QLocale::Brazil).toString(dt.toLocalTime(), QStringLiteral("dd/MM/yyyy HH:mm")) : iso;
}

// Package versions are dates by convention (YYYY.M.D[.N]).
QDate versionDate(const QString& version) {
    const auto v = gk::updates::parsePackageVersion(version);
    return v ? QDate((*v)[0], (*v)[1], (*v)[2]) : QDate();
}

QString componentLabel(const QString& c) {
    if (c == "clamav") return QStringLiteral("Assinaturas ClamAV");
    if (c == "yara") return QStringLiteral("Regras YARA");
    if (c == "ioc") return QStringLiteral("Indicadores locais (IOC)");
    return c;
}

}  // namespace

QString UpdatesPage::describeError(const QString& code) {
    static const QHash<QString, QString> messages{
        {"not_a_package", "O arquivo não é um pacote de atualização do Game Kernel (.gkpkg)."},
        {"unsupported_format", "Versão de formato de pacote não suportada por esta versão do programa."},
        {"invalid_header", "Pacote corrompido (cabeçalho inválido)."},
        {"truncated", "Pacote incompleto ou corrompido."},
        {"no_trusted_keys", "Nenhuma chave pública confiável está instalada. Adicione a chave do publicador."},
        {"bad_signature", "Assinatura inválida ou de uma chave não confiável. Não use este pacote."},
        {"invalid_manifest", "O pacote é assinado, mas tem conteúdo proibido ou malformado."},
        {"incompatible_app", "O pacote exige uma versão mais nova do Game Kernel."},
        {"hash_mismatch", "Um arquivo do pacote foi adulterado depois da assinatura."},
        {"trailing_data", "O pacote contém dados extras após o conteúdo assinado."},
        {"downgrade", "A versão do pacote é igual ou mais antiga que a instalada."},
        {"validation_failed", "O conteúdo não passou na validação (ex.: regra YARA com erro). Nada foi alterado."},
        {"busy", "Outra instalação está em andamento ou as assinaturas estão em uso."},
        {"no_previous", "Não há versão anterior para restaurar."},
        {"io_error", "Falha de leitura ou gravação."},
        {"cancelled", "Operação cancelada."},
    };
    return messages.value(code, QStringLiteral("Erro: %1").arg(code));
}

UpdatesPage::UpdatesPage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    setObjectName(QStringLiteral("page"));
    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    auto* content = new QWidget(scroll);
    content->setObjectName(QStringLiteral("page"));
    auto* col = new QVBoxLayout(content);
    col->setContentsMargins(0, 0, 8, 0);
    col->setSpacing(16);
    scroll->setWidget(content);
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->addWidget(scroll);

    // ---- active set
    auto* state = new Card(QStringLiteral("Assinaturas instaladas"), content);
    auto* stateRow = new QHBoxLayout;
    statePill_ = new StatusPill(QStringLiteral("—"), StatusPill::Tone::Neutral, state);
    summary_ = new QLabel(state);
    summary_->setWordWrap(true);
    stateRow->addWidget(statePill_, 0, Qt::AlignTop);
    stateRow->addWidget(summary_, 1);
    state->body()->addLayout(stateRow);
    components_ = makeTable({"Componente", "Versão", "Itens", "Arquivos"}, state);
    state->body()->addWidget(components_);
    auto* buttons = new QHBoxLayout;
    importButton_ = new QPushButton(icon(QStringLiteral("upload"), Qt::white), QStringLiteral("Importar pacote…"), state);
    importButton_->setProperty("primary", true);
    rollbackButton_ = new QPushButton(icon(QStringLiteral("rotate-ccw")), QStringLiteral("Reverter para a versão anterior"), state);
    auto* refreshButton = new QPushButton(icon(QStringLiteral("refresh")), QStringLiteral("Atualizar"), state);
    buttons->addWidget(importButton_);
    buttons->addWidget(rollbackButton_);
    buttons->addStretch();
    buttons->addWidget(refreshButton);
    state->body()->addLayout(buttons);
    operation_ = new QLabel(state);
    operation_->setWordWrap(true);
    operation_->setProperty("muted", true);
    state->body()->addWidget(operation_);
    col->addWidget(state);

    // ---- trusted keys
    auto* keysCard = new Card(QStringLiteral("Chaves públicas confiáveis"), content);
    auto* keysHelp = new QLabel(QStringLiteral("Só pacotes assinados por uma destas chaves são aceitos. Adicione apenas chaves "
                                               "recebidas do publicador por um meio confiável e confira o identificador."),
                                keysCard);
    keysHelp->setWordWrap(true);
    keysHelp->setProperty("muted", true);
    keysCard->body()->addWidget(keysHelp);
    keys_ = makeTable({"Identificador", "Origem", "Arquivo"}, keysCard);
    keysCard->body()->addWidget(keys_);
    auto* keyButtons = new QHBoxLayout;
    auto* addKey = new QPushButton(icon(QStringLiteral("key")), QStringLiteral("Adicionar chave…"), keysCard);
    removeKeyButton_ = new QPushButton(icon(QStringLiteral("trash"), palette::Critical), QStringLiteral("Remover chave"), keysCard);
    removeKeyButton_->setProperty("danger", true);
    keyButtons->addWidget(addKey);
    keyButtons->addWidget(removeKeyButton_);
    keyButtons->addStretch();
    keysCard->body()->addLayout(keyButtons);
    col->addWidget(keysCard);

    // ---- history + limitations
    auto* historyCard = new Card(QStringLiteral("Histórico de instalações"), content);
    history_ = makeTable({"Instalado em", "Versão", "Componentes", "Chave", "Observação"}, historyCard);
    historyCard->body()->addWidget(history_);
    col->addWidget(historyCard);
    auto* limits = new Card(QStringLiteral("Como funciona"), content);
    auto* limitsText = new QLabel(
        QStringLiteral("O Game Kernel nunca baixa nada. As assinaturas só são atualizadas por pacotes .gkpkg levados ao "
                       "computador (pendrive ou pasta local). Antes de instalar, o pacote é verificado: assinatura Ed25519 "
                       "de uma chave confiável, integridade de cada arquivo e validação do conteúdo (as regras YARA são "
                       "compiladas). A troca é atômica: se algo falhar, nada muda. Sem atualizações, ameaças novas podem "
                       "não ser reconhecidas por assinatura."),
        limits);
    limitsText->setWordWrap(true);
    limitsText->setProperty("muted", true);
    limits->body()->addWidget(limitsText);
    col->addWidget(limits);
    col->addStretch();

    connect(importButton_, &QPushButton::clicked, this, &UpdatesPage::chooseAndImport);
    connect(rollbackButton_, &QPushButton::clicked, this, &UpdatesPage::rollbackToPrevious);
    connect(refreshButton, &QPushButton::clicked, this, &UpdatesPage::refresh);
    connect(addKey, &QPushButton::clicked, this, &UpdatesPage::chooseAndAddKey);
    connect(removeKeyButton_, &QPushButton::clicked, this, [this] {
        const int row = keys_->currentRow();
        if (row >= 0) removeTrustedKey(keys_->item(row, 0)->text());
    });
    connect(keys_, &QTableWidget::itemSelectionChanged, this, [this] {
        const int row = keys_->currentRow();
        removeKeyButton_->setEnabled(row >= 0 && keys_->item(row, 1)->text() == QStringLiteral("Adicionada pelo usuário"));
    });
    refresh();
}

QString UpdatesPage::activeVersion() const { return active_.value("package_version").toString(); }

void UpdatesPage::refresh() {
    const auto installer = ctx_->makeInstaller();
    active_ = installer->activeManifest().value_or(QJsonObject{});
    components_->setRowCount(0);
    history_->setRowCount(0);
    if (active_.isEmpty()) {
        stale_ = true;
        statePill_->set(QStringLiteral("Nenhum pacote"), StatusPill::Tone::Warning);
        summary_->setText(QStringLiteral("Nenhum pacote de atualização foi instalado. Importe um pacote .gkpkg do publicador."));
    } else {
        const QDate date = versionDate(activeVersion());
        const int maxDays = ctx_->setting(QStringLiteral("updates.stale_after_days"), 7).toInt(7);
        const qint64 age = date.isValid() ? date.daysTo(QDate::currentDate()) : -1;
        stale_ = age < 0 || age > maxDays;
        statePill_->set(stale_ ? QStringLiteral("Desatualizadas") : QStringLiteral("Atualizadas"),
                        stale_ ? StatusPill::Tone::Warning : StatusPill::Tone::Good);
        QString text = QStringLiteral("Pacote <b>%1</b> de <b>%2</b>, instalado em %3 (chave %4).")
                           .arg(activeVersion().toHtmlEscaped(), active_.value("publisher").toString().toHtmlEscaped(),
                                formatIso(active_.value("installed_at").toString()),
                                active_.value("signing_key_id").toString());
        if (age >= 0)
            text += QStringLiteral("<br>Assinaturas de %1 (há %2 dia(s); prazo configurado: %3 dias).")
                        .arg(QLocale(QLocale::Portuguese, QLocale::Brazil).toString(date, QStringLiteral("dd/MM/yyyy")))
                        .arg(age).arg(maxDays);
        if (stale_) text += QStringLiteral("<br><b>Importe um pacote mais recente:</b> ameaças novas podem não ser reconhecidas.");
        summary_->setText(text);
        const QJsonObject comps = active_.value("components").toObject();
        for (auto it = comps.begin(); it != comps.end(); ++it) {
            const QJsonObject c = it.value().toObject();
            const int row = components_->rowCount();
            components_->insertRow(row);
            QStringList files;
            for (const auto& f : c.value("files").toArray()) files << f.toString();
            setRow(components_, row, {componentLabel(it.key()), c.value("version").toString(),
                                      QString::number(qint64(c.value("count").toDouble())), files.join(", ")});
        }
        const QJsonArray hist = active_.value("history").toArray();
        for (qsizetype i = hist.size() - 1; i >= 0; --i) {
            const QJsonObject h = hist[i].toObject();
            QStringList comps2;
            for (const auto& c : h.value("components").toArray()) comps2 << componentLabel(c.toString());
            const int row = history_->rowCount();
            history_->insertRow(row);
            setRow(history_, row, {formatIso(h.value("installed_at").toString()), h.value("package_version").toString(),
                                   comps2.join(", "), h.value("signing_key_id").toString(),
                                   h.value("downgrade").toBool() ? QStringLiteral("reversão confirmada") : QString()});
        }
    }
    fitTableToContents(components_);
    fitTableToContents(history_);
    rollbackButton_->setEnabled(!busy_ && QDir(installer->previousDir()).exists() && !active_.isEmpty());
    importButton_->setEnabled(!busy_);
    fillKeys();
}

void UpdatesPage::fillKeys() {
    keys_->setRowCount(0);
    const auto add = [this](const QString& dir, const QString& origin) {
        for (const auto& key : gk::updates::loadTrustedKeys({dir})) {
            const int row = keys_->rowCount();
            keys_->insertRow(row);
            setRow(keys_, row, {key.id, origin, QFileInfo(key.source).fileName()});
        }
    };
    add(ctx_->builtinKeysDir(), QStringLiteral("Embutida no programa"));
    add(ctx_->userKeysDir(), QStringLiteral("Adicionada pelo usuário"));
    fitTableToContents(keys_);
    removeKeyButton_->setEnabled(false);
}

void UpdatesPage::setBusy(bool busy, const QString& what) {
    busy_ = busy;
    importButton_->setEnabled(!busy);
    rollbackButton_->setEnabled(!busy && !active_.isEmpty());
    if (busy) operation_->setText(what);
}

void UpdatesPage::finishOperation(bool ok, const QString& code, const QString& message, const QStringList& details) {
    setBusy(false);
    QString text = message;
    if (!details.isEmpty()) text += QStringLiteral("\n• ") + details.mid(0, 8).join(QStringLiteral("\n• "));
    operation_->setText(text);
    emit ctx_->notify(ok ? AppContext::Level::Success : (code == "cancelled" ? AppContext::Level::Info : AppContext::Level::Error),
                      ok ? QStringLiteral("Atualização offline") : QStringLiteral("Pacote não instalado"), message);
    refresh();
    emit operationFinished(ok, code, message);
}

void UpdatesPage::chooseAndImport() {
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Importar pacote de atualização"), QString(),
                                                      QStringLiteral("Pacotes do Game Kernel (*.gkpkg)"));
    if (!path.isEmpty()) importPackage(path);
}

void UpdatesPage::importPackage(const QString& packagePath) {
    if (busy_) return;
    setBusy(true, QStringLiteral("Verificando assinatura e integridade de %1…").arg(QFileInfo(packagePath).fileName()));
    auto* watcher = new QFutureWatcher<gk::updates::VerifyResult>(this);
    connect(watcher, &QFutureWatcher<gk::updates::VerifyResult>::finished, this, [this, watcher, packagePath] {
        const gk::updates::VerifyResult r = watcher->result();
        watcher->deleteLater();
        if (!r.ok) return finishOperation(false, r.error.code, describeError(r.error.code) + "\n" + r.error.message);
        const auto& m = r.manifest;
        QStringList comps;
        for (auto it = m.components.begin(); it != m.components.end(); ++it)
            comps << QStringLiteral("%1 %2").arg(componentLabel(it.key()), it.value().toObject().value("version").toString());
        qint64 total = 0;
        for (const auto& f : m.files) total += f.size;
        const QString details = QStringLiteral(
            "O pacote foi verificado: assinatura Ed25519 válida da chave confiável %1 e integridade de todos os arquivos.\n\n"
            "Publicador: %2\nVersão: %3\nComponentes: %4\nArquivos: %5 (%6 KB)\n\nInstalar este pacote?")
            .arg(r.keyId, m.publisher, m.packageVersion, comps.join("; ")).arg(m.files.size()).arg(total / 1024);
        if (!ctx_->ask(this, QStringLiteral("Instalar atualização offline"), details))
            return finishOperation(false, QStringLiteral("cancelled"), describeError(QStringLiteral("cancelled")));
        installVerified(packagePath, false);
    });
    const AppContext* ctx = ctx_;
    watcher->setFuture(QtConcurrent::run([ctx, packagePath] { return ctx->makeInstaller()->inspect(packagePath); }));
}

void UpdatesPage::installVerified(const QString& packagePath, bool allowDowngrade) {
    setBusy(true, QStringLiteral("Instalando e validando o conteúdo (regras YARA, bases ClamAV, indicadores)…"));
    auto* watcher = new QFutureWatcher<gk::updates::InstallReport>(this);
    connect(watcher, &QFutureWatcher<gk::updates::InstallReport>::finished, this, [this, watcher, packagePath, allowDowngrade] {
        const gk::updates::InstallReport rep = watcher->result();
        watcher->deleteLater();
        if (rep.ok)
            return finishOperation(true, {}, QStringLiteral("Assinaturas atualizadas para o pacote %1.").arg(rep.packageVersion),
                                   rep.details);
        if (rep.error.code == "downgrade" && !allowDowngrade) {
            const bool go = ctx_->ask(this, QStringLiteral("Instalar versão mais antiga?"),
                                      QStringLiteral("O pacote %1 não é mais novo que o instalado (%2). Instalar uma versão "
                                                     "antiga reduz a proteção e só deve ser feito para reverter um problema.\n\n"
                                                     "Instalar mesmo assim?")
                                          .arg(rep.packageVersion, rep.previousPackageVersion));
            if (go) return installVerified(packagePath, true);
        }
        finishOperation(false, rep.error.code, describeError(rep.error.code) + "\n" + rep.error.message, rep.details);
    });
    const AppContext* ctx = ctx_;
    watcher->setFuture(QtConcurrent::run([ctx, packagePath, allowDowngrade] {
        gk::updates::InstallOptions options;
        options.allowDowngrade = allowDowngrade;
        return ctx->makeInstaller()->install(packagePath, options);
    }));
}

void UpdatesPage::rollbackToPrevious() {
    if (busy_) return;
    if (!ctx_->ask(this, QStringLiteral("Reverter assinaturas"),
                   QStringLiteral("Restaurar o conjunto de assinaturas anterior? O conjunto atual passa a ser o anterior "
                                  "e pode ser restaurado da mesma forma.")))
        return finishOperation(false, QStringLiteral("cancelled"), describeError(QStringLiteral("cancelled")));
    setBusy(true, QStringLiteral("Restaurando o conjunto anterior…"));
    auto* watcher = new QFutureWatcher<gk::updates::InstallReport>(this);
    connect(watcher, &QFutureWatcher<gk::updates::InstallReport>::finished, this, [this, watcher] {
        const gk::updates::InstallReport rep = watcher->result();
        watcher->deleteLater();
        if (rep.ok)
            return finishOperation(true, {}, QStringLiteral("Assinaturas revertidas para o pacote %1.").arg(rep.packageVersion));
        finishOperation(false, rep.error.code, describeError(rep.error.code) + "\n" + rep.error.message, rep.details);
    });
    const AppContext* ctx = ctx_;
    watcher->setFuture(QtConcurrent::run([ctx] { return ctx->makeInstaller()->rollback(); }));
}

void UpdatesPage::chooseAndAddKey() {
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Adicionar chave pública confiável"), QString(),
                                                      QStringLiteral("Chave pública (*.pub)"));
    if (!path.isEmpty()) addTrustedKey(path);
}

bool UpdatesPage::addTrustedKey(const QString& pubPath) {
    QFile f(pubPath);
    std::optional<gk::updates::TrustedKey> key;
    if (f.size() <= 4096 && f.open(QIODevice::ReadOnly)) key = gk::updates::parsePublicKeyPem(f.readAll(), pubPath);
    if (!key) {
        emit ctx_->notify(AppContext::Level::Error, QStringLiteral("Chave recusada"),
                          QStringLiteral("O arquivo não contém uma chave pública Ed25519 válida."));
        return false;
    }
    if (!ctx_->ask(this, QStringLiteral("Confiar nesta chave?"),
                   QStringLiteral("Identificador da chave: %1\n\nPacotes assinados por ela poderão alterar as assinaturas de "
                                  "detecção. Confira o identificador com o publicador por um meio confiável.\n\nConfiar?")
                       .arg(key->id)))
        return false;
    QDir().mkpath(ctx_->userKeysDir());
    const QString target = QDir(ctx_->userKeysDir()).filePath(key->id + QStringLiteral(".pub"));
    QFile::remove(target);
    if (!QFile::copy(pubPath, target)) {
        emit ctx_->notify(AppContext::Level::Error, QStringLiteral("Chave não adicionada"), QStringLiteral("Falha ao gravar a chave."));
        return false;
    }
    emit ctx_->notify(AppContext::Level::Success, QStringLiteral("Chave adicionada"), QStringLiteral("Chave %1 agora é confiável.").arg(key->id));
    fillKeys();
    return true;
}

bool UpdatesPage::removeTrustedKey(const QString& keyId) {
    for (const auto& key : gk::updates::loadTrustedKeys({ctx_->userKeysDir()})) {
        if (key.id != keyId) continue;
        if (!ctx_->ask(this, QStringLiteral("Remover chave"),
                       QStringLiteral("Deixar de confiar na chave %1? Pacotes assinados por ela serão recusados.").arg(keyId)))
            return false;
        const bool removed = QFile::remove(key.source);
        emit ctx_->notify(removed ? AppContext::Level::Success : AppContext::Level::Error, QStringLiteral("Chaves confiáveis"),
                          removed ? QStringLiteral("Chave %1 removida.").arg(keyId) : QStringLiteral("Falha ao remover a chave."));
        fillKeys();
        return removed;
    }
    return false;   // built-in keys cannot be removed from the UI
}

}  // namespace gk::app
