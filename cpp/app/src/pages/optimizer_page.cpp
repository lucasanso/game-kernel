#include "optimizer_page.hpp"

#include "../ui_kit.hpp"

#include <QDir>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QPushButton>
#include <QVBoxLayout>

namespace gk::app {

namespace {

constexpr int kMinAgeHours = 24;

QString bytesText(qint64 bytes) { return QLocale().formattedDataSize(bytes, 1, QLocale::DataSizeTraditionalFormat); }

void pillFor(StatusPill* pill, const QString& status) {
    if (status == QLatin1String("ok")) pill->set(QStringLiteral("OK"), StatusPill::Tone::Good);
    else if (status == QLatin1String("attention")) pill->set(QStringLiteral("Atenção"), StatusPill::Tone::Warning);
    else if (status == QLatin1String("info")) pill->set(QStringLiteral("Informação"), StatusPill::Tone::Accent);
    else pill->set(QStringLiteral("Indisponível"), StatusPill::Tone::Neutral);
}

}  // namespace

OptimizerPage::OptimizerPage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);

    auto* diag = new Card(QStringLiteral("Diagnóstico para jogos"), content);
    diag->body()->addWidget(mutedLabel(QStringLiteral("O otimizador não muda configurações do Windows: ele lê o que afeta os jogos "
                                                      "neste computador e diz o que vale ajustar e onde fazer isso no próprio "
                                                      "Windows."),
                                       diag));
    auto* head = new QHBoxLayout;
    summary_ = mutedLabel(QStringLiteral("Verificando…"), diag);
    head->addWidget(summary_, 1);
    recheck_ = new QPushButton(icon(QStringLiteral("refresh")), QStringLiteral("Verificar de novo"), diag);
    head->addWidget(recheck_, 0, Qt::AlignTop);
    diag->body()->addLayout(head);
    checkList_ = new QVBoxLayout;
    checkList_->setSpacing(10);
    diag->body()->addLayout(checkList_);
    col->addWidget(diag);

    auto* temp = new Card(QStringLiteral("Arquivos temporários"), content);
    QStringList roots;
    for (const QString& r : ctx_->optimizer()->tempRoots()) roots << QDir::toNativeSeparators(r);
    tempInfo_ = mutedLabel(QStringLiteral("Apaga só arquivos com mais de %1 horas sem alteração em: %2. Arquivos em uso ficam, links e "
                                          "atalhos de pasta não são seguidos, e só é apagado o que a análise listou e não mudou "
                                          "desde então. Isso não pode ser desfeito.")
                               .arg(kMinAgeHours)
                               .arg(roots.join(QStringLiteral("; "))),
                           temp);
    temp->body()->addWidget(tempInfo_);
    tempStatus_ = new QLabel(QStringLiteral("Analise para ver quanto espaço pode ser liberado."), temp);
    tempStatus_->setWordWrap(true);
    temp->body()->addWidget(tempStatus_);
    auto* tempRow = new QHBoxLayout;
    analyze_ = new QPushButton(icon(QStringLiteral("search")), QStringLiteral("Analisar"), temp);
    clean_ = new QPushButton(icon(QStringLiteral("trash"), Qt::white), QStringLiteral("Limpar"), temp);
    clean_->setProperty("danger", true);
    clean_->setEnabled(false);
    tempRow->addWidget(analyze_);
    tempRow->addStretch();
    tempRow->addWidget(clean_);
    temp->body()->addLayout(tempRow);
    col->addWidget(temp);
    col->addStretch();

    auto* opt = ctx_->optimizer();
    connect(opt, &gk::bridge::OptimizerService::diagnosed, this, [this](qint64 request, const QJsonArray& checks) {
        if (request != diagRequest_) return;
        diagRequest_ = -1;
        recheck_->setEnabled(true);
        showChecks(checks);
    });
    connect(opt, &gk::bridge::OptimizerService::tempAnalyzed, this, [this](qint64 request, const QJsonObject& p) {
        if (request != tempRequest_) return;
        tempRequest_ = -1;
        plan_ = p;
        const qint64 files = p.value("files").toInteger();
        QString text = files > 0 ? QStringLiteral("%1 arquivo(s) antigo(s), %2, podem ser apagados.").arg(files).arg(bytesText(p.value("bytes").toInteger()))
                                 : QStringLiteral("Nada para limpar: nenhum arquivo temporário antigo.");
        if (p.value("recent").toInt() > 0)
            text += QStringLiteral(" %1 recente(s) mantido(s) (podem estar em uso).").arg(p.value("recent").toInt());
        if (p.value("links").toInt() > 0) text += QStringLiteral(" %1 link(s) ignorado(s).").arg(p.value("links").toInt());
        if (p.value("truncated").toBool()) text += QStringLiteral(" A lista parou no limite de arquivos; analise de novo depois.");
        tempStatus_->setText(text);
        analyze_->setEnabled(true);
        clean_->setEnabled(files > 0 && ctx_->optimizer()->hasPlan());
        emit tempAnalyzed(p);
    });
    connect(opt, &gk::bridge::OptimizerService::tempCleaned, this, [this](qint64 request, const QJsonObject& r) {
        if (request != tempRequest_) return;
        tempRequest_ = -1;
        QString text = QStringLiteral("%1 arquivo(s) apagado(s), %2 liberados.").arg(r.value("deleted").toInt()).arg(bytesText(r.value("bytes_freed").toInteger()));
        if (r.value("in_use").toInt() > 0) text += QStringLiteral(" %1 em uso ou protegido(s) mantido(s).").arg(r.value("in_use").toInt());
        if (r.value("changed").toInt() > 0)
            text += QStringLiteral(" %1 alterado(s) desde a análise mantido(s).").arg(r.value("changed").toInt());
        tempStatus_->setText(text);
        plan_ = {};
        analyze_->setEnabled(true);
        clean_->setEnabled(false);
        emit ctx_->notify(AppContext::Level::Success, QStringLiteral("Arquivos temporários"), text);
        emit tempCleaned(r);
    });
    connect(opt, &gk::bridge::OptimizerService::failed, this, [this](qint64 request, const QString& message) {
        if (request != tempRequest_) return;
        tempRequest_ = -1;
        tempStatus_->setText(QStringLiteral("Não foi possível: %1").arg(message));
        analyze_->setEnabled(true);
        clean_->setEnabled(false);
    });
    connect(recheck_, &QPushButton::clicked, this, &OptimizerPage::refreshDiagnostics);
    connect(analyze_, &QPushButton::clicked, this, &OptimizerPage::analyzeTemp);
    connect(clean_, &QPushButton::clicked, this, [this] { cleanTemp(); });
    refreshDiagnostics();
}

void OptimizerPage::refreshDiagnostics() {
    recheck_->setEnabled(false);
    summary_->setText(QStringLiteral("Verificando…"));
    diagRequest_ = ctx_->optimizer()->diagnose(ctx_->realtimeSettings().folders);
}

void OptimizerPage::showChecks(const QJsonArray& checks) {
    checks_ = checks;
    while (QLayoutItem* item = checkList_->takeAt(0)) {
        delete item->widget();
        delete item;
    }
    int attention = 0;
    for (const auto& v : checks) {
        const QJsonObject c = v.toObject();
        const QString status = c.value("status").toString();
        if (status == QLatin1String("attention")) ++attention;
        auto* row = new QFrame(this);
        row->setObjectName(QStringLiteral("checkRow"));
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(0, 4, 0, 4);
        auto* pill = new StatusPill(QString(), StatusPill::Tone::Neutral, row);
        pill->setFixedWidth(104);
        pillFor(pill, status);
        h->addWidget(pill, 0, Qt::AlignTop);
        auto* texts = new QVBoxLayout;
        texts->setSpacing(2);
        auto* title = new QLabel(QStringLiteral("<b>%1</b> — %2").arg(c.value("title").toString().toHtmlEscaped(),
                                                                       c.value("value").toString().toHtmlEscaped()),
                                 row);
        title->setWordWrap(true);
        texts->addWidget(title);
        if (const QString detail = c.value("detail").toString(); !detail.isEmpty()) texts->addWidget(mutedLabel(detail, row));
        if (const QString rec = c.value("recommendation").toString(); !rec.isEmpty()) {
            auto* r = new QLabel(QStringLiteral("O que fazer: %1").arg(rec), row);
            r->setWordWrap(true);
            texts->addWidget(r);
        }
        h->addLayout(texts, 1);
        checkList_->addWidget(row);
    }
    summary_->setText(attention == 0 ? QStringLiteral("Nada pede atenção agora.")
                                     : QStringLiteral("%1 item(ns) pede(m) atenção.").arg(attention));
    emit diagnosed(checks.size());
}

void OptimizerPage::analyzeTemp() {
    if (tempRequest_ >= 0) return;
    analyze_->setEnabled(false);
    clean_->setEnabled(false);
    tempStatus_->setText(QStringLiteral("Analisando os arquivos temporários…"));
    tempRequest_ = ctx_->optimizer()->analyzeTemp(kMinAgeHours);
}

bool OptimizerPage::cleanTemp() {
    if (tempRequest_ >= 0 || !canClean()) return false;
    if (!ctx_->ask(this, QStringLiteral("Limpar arquivos temporários"),
                   QStringLiteral("Apagar %1 arquivo(s) temporário(s) antigo(s) (%2)?\n\nSó os arquivos listados na análise e que não "
                                  "mudaram desde então são apagados. Isso não pode ser desfeito.")
                       .arg(plan_.value("files").toInteger())
                       .arg(bytesText(plan_.value("bytes").toInteger()))))
        return false;
    analyze_->setEnabled(false);
    clean_->setEnabled(false);
    tempStatus_->setText(QStringLiteral("Apagando…"));
    tempRequest_ = ctx_->optimizer()->cleanTemp();
    return true;
}

bool OptimizerPage::canClean() const { return ctx_->optimizer()->hasPlan() && plan_.value("files").toInteger() > 0; }

QString OptimizerPage::checkStatus(const QString& id) const {
    for (const auto& v : checks_)
        if (v.toObject().value("id").toString() == id) return v.toObject().value("status").toString();
    return {};
}

QString OptimizerPage::diagnosticsSummary() const { return summary_->text(); }

QString OptimizerPage::tempText() const { return tempStatus_->text(); }

}  // namespace gk::app
