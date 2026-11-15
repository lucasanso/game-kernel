#include "dashboard_page.hpp"

#include "../ui_kit.hpp"
#include "scan_table.hpp"

#include "gk/updates/installer.hpp"

#include <QDate>
#include <QDir>
#include <QFileDialog>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QPushButton>
#include <QRegularExpression>

namespace gk::app {

namespace {

struct Tile {
    Card* card;
    StatusPill* pill;
    QLabel* text;
    QHBoxLayout* actions;
};

Tile makeTile(const QString& title, QWidget* parent) {
    Tile t;
    t.card = new Card(title, parent);
    t.pill = new StatusPill(QStringLiteral("…"), StatusPill::Tone::Neutral, t.card);
    t.card->body()->addWidget(t.pill, 0, Qt::AlignLeft);
    t.text = mutedLabel(QString(), t.card);
    t.card->body()->addWidget(t.text);
    t.card->body()->addStretch();
    t.actions = new QHBoxLayout;
    t.actions->addStretch();
    t.card->body()->addLayout(t.actions);
    return t;
}

// Package versions are YYYY.MM.DD.N (contracts/update_package.md).
QDate packageDate(const QString& version) {
    const auto m = QRegularExpression(QStringLiteral("^(\\d{4})\\.(\\d{1,2})\\.(\\d{1,2})\\.")).match(version);
    return m.hasMatch() ? QDate(m.captured(1).toInt(), m.captured(2).toInt(), m.captured(3).toInt()) : QDate();
}

}  // namespace

DashboardPage::DashboardPage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);

    auto* grid = new QGridLayout;
    grid->setSpacing(16);
    Tile scan = makeTile(QStringLiteral("Última varredura"), content);
    scanPill_ = scan.pill;
    scanText_ = scan.text;
    openLast_ = new QPushButton(icon(QStringLiteral("file-search")), QStringLiteral("Ver análise"), scan.card);
    scan.actions->addWidget(openLast_);
    Tile sig = makeTile(QStringLiteral("Assinaturas"), content);
    sigPill_ = sig.pill;
    sigText_ = sig.text;
    auto* updates = new QPushButton(icon(QStringLiteral("package")), QStringLiteral("Atualização offline"), sig.card);
    sig.actions->addWidget(updates);
    Tile quarantine = makeTile(QStringLiteral("Quarentena"), content);
    quarantinePill_ = quarantine.pill;
    quarantineText_ = quarantine.text;
    auto* openQ = new QPushButton(icon(QStringLiteral("archive")), QStringLiteral("Abrir quarentena"), quarantine.card);
    quarantine.actions->addWidget(openQ);
    Tile integrity = makeTile(QStringLiteral("Integridade da instalação"), content);
    integrityPill_ = integrity.pill;
    integrityText_ = integrity.text;
    auto* recheck = new QPushButton(icon(QStringLiteral("refresh")), QStringLiteral("Verificar de novo"), integrity.card);
    integrity.actions->addWidget(recheck);
    Tile realtime = makeTile(QStringLiteral("Proteção em tempo real"), content);
    realtimePill_ = realtime.pill;
    realtimeText_ = realtime.text;
    auto* openRealtime = new QPushButton(icon(QStringLiteral("eye")), QStringLiteral("Configurar"), realtime.card);
    realtime.actions->addWidget(openRealtime);
    grid->addWidget(scan.card, 0, 0);
    grid->addWidget(sig.card, 0, 1);
    grid->addWidget(quarantine.card, 1, 0);
    grid->addWidget(integrity.card, 1, 1);
    grid->addWidget(realtime.card, 2, 0, 1, 2);
    col->addLayout(grid);

    auto* quick = new Card(QStringLiteral("Ações rápidas"), content);
    quick->body()->addWidget(mutedLabel(QStringLiteral("A análise só lê os arquivos: nada é executado, movido ou apagado sem você "
                                                       "pedir. Nenhum dado sai deste computador."),
                                        quick));
    auto* quickRow = new QHBoxLayout;
    auto* scanFolder = new QPushButton(icon(QStringLiteral("search"), Qt::white), QStringLiteral("Analisar uma pasta de jogo…"), quick);
    scanFolder->setProperty("primary", true);
    auto* history = new QPushButton(icon(QStringLiteral("clock")), QStringLiteral("Histórico"), quick);
    quickRow->addWidget(scanFolder);
    quickRow->addWidget(history);
    quickRow->addStretch();
    quick->body()->addLayout(quickRow);
    col->addWidget(quick);
    col->addStretch();

    connect(ctx_->history(), &gk::bridge::HistoryService::scansListed, this, [this](qint64 request, const QJsonArray& scans) {
        if (request != scansRequest_) return;
        scansRequest_ = -1;
        if (scans.isEmpty()) {
            lastScanId_ = -1;
            scanPill_->set(QStringLiteral("Nenhuma ainda"), StatusPill::Tone::Neutral);
            scanText_->setText(QStringLiteral("Analise a pasta de um jogo, crack, repack ou mod para começar."));
        } else {
            const QJsonObject s = scans.first().toObject();
            lastScanId_ = s.value("scan_id").toInteger();
            const qint64 threats = s.value("threats").toInteger();
            const qint64 suspicious = s.value("suspicious").toInteger() + s.value("pua").toInteger();
            if (s.value("status").toString() == QLatin1String("failed"))
                scanPill_->set(QStringLiteral("Falhou"), StatusPill::Tone::Bad);
            else if (threats > 0)
                scanPill_->set(QStringLiteral("%1 ameaça(s)").arg(threats), StatusPill::Tone::Bad);
            else if (suspicious > 0)
                scanPill_->set(QStringLiteral("%1 suspeito(s)").arg(suspicious), StatusPill::Tone::Warning);
            else
                scanPill_->set(QStringLiteral("Nada encontrado"), StatusPill::Tone::Good);
            QStringList targets;
            for (const auto& t : s.value("targets").toArray()) targets << QDir::toNativeSeparators(t.toString());
            scanText_->setText(QStringLiteral("%1 — %2, %3 arquivos. Risco máximo: %4.\n%5")
                                   .arg(scanWhen(s.value("started_at")), scanStatusLabel(s.value("status").toString()).toLower())
                                   .arg(s.value("files_found").toInteger())
                                   .arg(riskLabel(s.value("max_risk_level").toString()), targets.join(QStringLiteral("; "))));
        }
        openLast_->setEnabled(lastScanId_ > 0);
        if (--pending_ == 0) emit refreshed();
    });
    connect(ctx_->history(), &gk::bridge::HistoryService::failed, this, [this](qint64 request, const QString& message) {
        if (request != scansRequest_) return;
        scansRequest_ = -1;
        scanPill_->set(QStringLiteral("Indisponível"), StatusPill::Tone::Bad);
        scanText_->setText(message);
        if (--pending_ == 0) emit refreshed();
    });
    connect(ctx_->quarantine(), &gk::bridge::QuarantineService::listed, this, [this](qint64 request, const QJsonArray& items) {
        if (request != quarantineRequest_) return;
        quarantineRequest_ = -1;
        quarantinePill_->set(items.isEmpty() ? QStringLiteral("Vazia") : QStringLiteral("%1 item(ns)").arg(items.size()),
                             items.isEmpty() ? StatusPill::Tone::Good : StatusPill::Tone::Accent);
        quarantineText_->setText(items.isEmpty() ? QStringLiteral("Nenhum arquivo em quarentena.")
                                                 : QStringLiteral("Arquivos guardados criptografados; restaure ou apague pela página Quarentena."));
        if (--pending_ == 0) emit refreshed();
    });
    connect(ctx_->integrity(), &gk::bridge::IntegrityService::checked, this, [this](const QJsonObject& r) {
        if (r.value("ok").toBool()) {
            integrityPill_->set(QStringLiteral("Verificada"), StatusPill::Tone::Good);
            integrityText_->setText(QStringLiteral("%1 componentes conferidos com o manifesto%2.")
                                        .arg(r.value("verified").toInteger())
                                        .arg(r.value("signature_valid").toBool() ? QStringLiteral(" assinado (chave %1)").arg(r.value("signer_key_id").toString())
                                                                                 : QStringLiteral(" sem assinatura (build local)")));
        } else if (!r.value("manifest_present").toBool()) {
            integrityPill_->set(QStringLiteral("Sem manifesto"), StatusPill::Tone::Warning);
            integrityText_->setText(r.value("detail").toString());
        } else {
            integrityPill_->set(QStringLiteral("ALTERADA"), StatusPill::Tone::Bad);
            QStringList files;
            for (const auto& f : r.value("modified").toArray()) files << f.toString();
            for (const auto& f : r.value("missing").toArray()) files << f.toString();
            integrityText_->setText(r.value("detail").toString() + QStringLiteral("\n") + files.mid(0, 5).join(QStringLiteral(", ")) +
                                    QStringLiteral("\nReinstale o Game Kernel."));
        }
        if (--pending_ == 0) emit refreshed();
    });
    connect(openLast_, &QPushButton::clicked, this, [this] {
        if (lastScanId_ > 0) emit openResults(lastScanId_);
    });
    connect(updates, &QPushButton::clicked, this, &DashboardPage::openUpdates);
    connect(openQ, &QPushButton::clicked, this, &DashboardPage::openQuarantine);
    connect(openRealtime, &QPushButton::clicked, this, &DashboardPage::openRealtime);
    connect(ctx_->realtime(), &gk::bridge::RealtimeService::statusChanged, this, &DashboardPage::showRealtime);
    connect(history, &QPushButton::clicked, this, &DashboardPage::openHistory);
    connect(recheck, &QPushButton::clicked, this, [this] {
        integrityPill_->set(QStringLiteral("Verificando…"), StatusPill::Tone::Neutral);
        ++pending_;
        ctx_->integrity()->check();
    });
    connect(scanFolder, &QPushButton::clicked, this, [this] {
        const QString dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Pasta do jogo, crack, repack ou mod"));
        if (!dir.isEmpty()) emit requestScan(dir);
    });
    connect(ctx_, &AppContext::settingChanged, this, [this](const QString& key) {
        if (key == QLatin1String("updates.stale_after_days")) showSignatures();
    });
    showRealtime(ctx_->realtime()->status());
    refresh();
}

void DashboardPage::showRealtime(const QJsonObject& st) {
    int watching = 0, problems = 0;
    for (const auto& v : st.value("folders").toArray()) (v.toObject().value("watching").toBool() ? watching : problems)++;
    if (!st.value("enabled").toBool()) {
        realtimePill_->set(QStringLiteral("Desativada"), StatusPill::Tone::Warning);
        realtimeText_->setText(QStringLiteral("Ative para analisar automaticamente o que aparecer nas pastas dos seus jogos e downloads."));
    } else if (!st.value("active").toBool()) {
        realtimePill_->set(QStringLiteral("Nenhuma pasta observada"), StatusPill::Tone::Bad);
        realtimeText_->setText(QStringLiteral("As pastas escolhidas não puderam ser observadas; veja a página Tempo real."));
    } else {
        realtimePill_->set(problems ? QStringLiteral("Ativa, com avisos") : QStringLiteral("Ativa"),
                           problems ? StatusPill::Tone::Warning : StatusPill::Tone::Good);
        realtimeText_->setText(QStringLiteral("%1 pasta(s) observada(s); %2 arquivo(s) analisado(s) e %3 achado(s) desde que o "
                                              "programa abriu.")
                                   .arg(watching)
                                   .arg(st.value("files_scanned").toInteger())
                                   .arg(st.value("detections").toInteger()));
    }
}

QString DashboardPage::realtimeText() const { return realtimePill_->text() + QStringLiteral(" — ") + realtimeText_->text(); }

void DashboardPage::refresh() {
    pending_ = 3;
    scansRequest_ = ctx_->history()->listScans(1);
    quarantineRequest_ = ctx_->quarantine()->list();
    integrityPill_->set(QStringLiteral("Verificando…"), StatusPill::Tone::Neutral);
    ctx_->integrity()->check();
    showSignatures();
}

void DashboardPage::showSignatures() {
    const auto active = ctx_->makeInstaller()->activeManifest();
    if (!active) {
        sigPill_->set(QStringLiteral("Regras da instalação"), StatusPill::Tone::Warning);
        sigText_->setText(QStringLiteral("Nenhum pacote de atualização instalado: valem as regras que vieram com o programa. "
                                         "Importe um pacote .gkpkg na Central de Atualização Offline."));
        return;
    }
    const QString version = active->value("package_version").toString();
    const QDate date = packageDate(version);
    const int maxDays = ctx_->setting(QStringLiteral("updates.stale_after_days"), 7).toInt(7);
    const qint64 age = date.isValid() ? date.daysTo(QDate::currentDate()) : -1;
    const bool stale = age < 0 || age > maxDays;
    sigPill_->set(stale ? QStringLiteral("Desatualizadas") : QStringLiteral("Em dia"),
                  stale ? StatusPill::Tone::Warning : StatusPill::Tone::Good);
    sigText_->setText(QStringLiteral("Pacote %1%2.").arg(version, age >= 0 ? QStringLiteral(" (%1 dia(s))").arg(age) : QString()));
}

QString DashboardPage::lastScanText() const { return scanPill_->text() + QStringLiteral(" — ") + scanText_->text(); }
QString DashboardPage::signaturesText() const { return sigPill_->text() + QStringLiteral(" — ") + sigText_->text(); }
QString DashboardPage::quarantineText() const { return quarantinePill_->text(); }
QString DashboardPage::integrityText() const { return integrityText_->text(); }
QString DashboardPage::integrityStatus() const { return integrityPill_->text(); }

}  // namespace gk::app
