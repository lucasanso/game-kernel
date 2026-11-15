#include "settings_page.hpp"

#include "../ui_kit.hpp"

#include <QCheckBox>
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QUrl>

namespace gk::app {

namespace {

// Defaults and ranges of gamekernel/config.py (the Python readers validate again).
constexpr bool kRedactUsername = true;
constexpr bool kIncludeHostname = false;
constexpr int kStaleDays = 7, kStaleMin = 1, kStaleMax = 365;
constexpr bool kSandboxEnabled = false;
constexpr int kSandboxTimeout = 120, kTimeoutMin = 30, kTimeoutMax = 1800;

QSpinBox* spin(int lo, int hi, QWidget* parent) {
    auto* s = new QSpinBox(parent);
    s->setRange(lo, hi);
    s->setButtonSymbols(QAbstractSpinBox::NoButtons);
    s->setToolTip(QStringLiteral("Entre %1 e %2.").arg(lo).arg(hi));
    s->setKeyboardTracking(false);   // write once the value is complete, not on every key
    return s;
}

QHBoxLayout* labelled(const QString& text, QWidget* field, QWidget* parent) {
    auto* row = new QHBoxLayout;
    row->addWidget(new QLabel(text, parent));
    row->addWidget(field);
    row->addStretch();
    return row;
}

}  // namespace

SettingsPage::SettingsPage(AppContext* ctx, QWidget* parent) : QWidget(parent), ctx_(ctx) {
    QVBoxLayout* col = nullptr;
    QWidget* content = scrollingPage(this, &col);

    auto* reports = new Card(QStringLiteral("Relatórios forenses"), content);
    redact_ = new QCheckBox(QStringLiteral("Ocultar o nome de usuário nos caminhos dos relatórios"), reports);
    hostname_ = new QCheckBox(QStringLiteral("Incluir o nome do computador nos relatórios"), reports);
    reports->body()->addWidget(redact_);
    reports->body()->addWidget(hostname_);
    reports->body()->addWidget(mutedLabel(QStringLiteral("São os padrões de cada relatório; a página Relatórios permite "
                                                         "mudar as opções só para um relatório."),
                                          reports));
    col->addWidget(reports);

    auto* updates = new Card(QStringLiteral("Atualização offline"), content);
    staleDays_ = spin(kStaleMin, kStaleMax, updates);
    updates->body()->addLayout(labelled(QStringLiteral("Avisar que as assinaturas estão desatualizadas depois de (dias):"),
                                        staleDays_, updates));
    updates->body()->addWidget(mutedLabel(QStringLiteral("Conta a partir da data do pacote instalado. Nada é baixado: "
                                                         "o aviso só lembra de importar um pacote novo."),
                                          updates));
    col->addWidget(updates);

    auto* sandbox = new Card(QStringLiteral("Análise comportamental"), content);
    sandboxEnabled_ = new QCheckBox(QStringLiteral("Ativar a análise comportamental (executa a amostra apenas dentro "
                                                   "de uma máquina virtual descartável e sem rede)"),
                                    sandbox);
    sandbox->body()->addWidget(sandboxEnabled_);
    sandboxTimeout_ = spin(kTimeoutMin, kTimeoutMax, sandbox);
    sandbox->body()->addLayout(labelled(QStringLiteral("Tempo de observação padrão (s):"), sandboxTimeout_, sandbox));
    auto* sysmonRow = new QHBoxLayout;
    sysmonLabel_ = new QLabel(sandbox);
    sysmonLabel_->setWordWrap(true);
    auto* sysmonChoose = new QPushButton(icon(QStringLiteral("file")), QStringLiteral("Escolher Sysmon…"), sandbox);
    sysmonClear_ = new QPushButton(icon(QStringLiteral("x")), QStringLiteral("Remover"), sandbox);
    sysmonRow->addWidget(sysmonLabel_, 1);
    sysmonRow->addWidget(sysmonChoose);
    sysmonRow->addWidget(sysmonClear_);
    sandbox->body()->addLayout(sysmonRow);
    sandbox->body()->addWidget(mutedLabel(QStringLiteral("Opcional. O Sysmon (Microsoft Sysinternals) não pode ser "
                                                         "redistribuído: se você tiver o Sysmon64.exe, ele é levado para "
                                                         "dentro da máquina virtual e melhora a detecção de injeção em "
                                                         "processos."),
                                          sandbox));
    col->addWidget(sandbox);

    auto* dataCard = new Card(QStringLiteral("Dados neste computador"), content);
    dataCard->body()->addWidget(mutedLabel(
        QStringLiteral("Pasta de dados: %1\nGuarda o banco de varreduras, os relatórios, as configurações, as "
                       "atualizações de assinaturas e a quarentena. Nada sai deste computador.")
            .arg(QDir::toNativeSeparators(ctx_->dataDir())),
        dataCard));
    auto* dataRow = new QHBoxLayout;
    dataRow->addStretch();
    auto* openData = new QPushButton(icon(QStringLiteral("folder")), QStringLiteral("Abrir pasta de dados"), dataCard);
    auto* defaults = new QPushButton(icon(QStringLiteral("rotate-ccw")), QStringLiteral("Restaurar padrões desta página"), dataCard);
    dataRow->addWidget(openData);
    dataRow->addWidget(defaults);
    dataCard->body()->addLayout(dataRow);
    col->addWidget(dataCard);
    col->addWidget(mutedLabel(QStringLiteral("Opções de varredura, motores, tempo real e quarentena ainda não são "
                                             "configuráveis pela interface; a varredura pelo gk-cli usa os valores padrão."),
                              content));
    col->addStretch();

    reload();
    connect(redact_, &QCheckBox::toggled, this, &SettingsPage::setRedactUsername);
    connect(hostname_, &QCheckBox::toggled, this, &SettingsPage::setIncludeHostname);
    connect(staleDays_, &QSpinBox::valueChanged, this, &SettingsPage::setStaleAfterDays);
    connect(sandboxEnabled_, &QCheckBox::toggled, this, &SettingsPage::setSandboxEnabled);
    connect(sandboxTimeout_, &QSpinBox::valueChanged, this, &SettingsPage::setSandboxTimeout);
    connect(sysmonChoose, &QPushButton::clicked, this, [this] {
        const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Escolher o Sysmon"), QString(),
                                                          QStringLiteral("Sysmon (Sysmon64.exe Sysmon.exe)"));
        if (!path.isEmpty() && !setSysmonPath(path))
            emit ctx_->notify(AppContext::Level::Error, QStringLiteral("Configurações"), error_);
    });
    connect(sysmonClear_, &QPushButton::clicked, this, [this] { setSysmonPath(QString()); });
    connect(openData, &QPushButton::clicked, this, [this] { QDesktopServices::openUrl(QUrl::fromLocalFile(ctx_->dataDir())); });
    connect(defaults, &QPushButton::clicked, this, &SettingsPage::restoreDefaults);
    connect(ctx_, &AppContext::settingChanged, this, &SettingsPage::reload);   // changes made by other pages
}

void SettingsPage::reload() {
    const QSignalBlocker b1(redact_), b2(hostname_), b3(staleDays_), b4(sandboxEnabled_), b5(sandboxTimeout_);
    redact_->setChecked(ctx_->setting(QStringLiteral("reports.redact_username"), kRedactUsername).toBool());
    hostname_->setChecked(ctx_->setting(QStringLiteral("reports.include_hostname"), kIncludeHostname).toBool());
    staleDays_->setValue(ctx_->setting(QStringLiteral("updates.stale_after_days"), kStaleDays).toInt(kStaleDays));
    sandboxEnabled_->setChecked(ctx_->setting(QStringLiteral("sandbox.enabled"), kSandboxEnabled).toBool());
    sandboxTimeout_->setValue(ctx_->setting(QStringLiteral("sandbox.timeout_seconds"), kSandboxTimeout).toInt(kSandboxTimeout));
    const QString sysmon = ctx_->setting(QStringLiteral("sandbox.sysmon_path"), QString()).toString();
    sysmonLabel_->setText(sysmon.isEmpty() ? QStringLiteral("Sysmon: não configurado.")
                                           : QStringLiteral("Sysmon: %1").arg(QDir::toNativeSeparators(sysmon)));
    sysmonClear_->setEnabled(!sysmon.isEmpty());
}

bool SettingsPage::write(const QString& key, const QJsonValue& value) {
    QString error;
    if (!ctx_->setSetting(key, value, &error)) {
        error_ = QStringLiteral("Não foi possível gravar as configurações: %1").arg(error);
        emit ctx_->notify(AppContext::Level::Error, QStringLiteral("Configurações"), error_);
        reload();
        return false;
    }
    error_.clear();
    return true;
}

bool SettingsPage::setRedactUsername(bool on) { return write(QStringLiteral("reports.redact_username"), on); }
bool SettingsPage::setIncludeHostname(bool on) { return write(QStringLiteral("reports.include_hostname"), on); }
bool SettingsPage::setSandboxEnabled(bool on) { return write(QStringLiteral("sandbox.enabled"), on); }

bool SettingsPage::setStaleAfterDays(int days) {
    if (days < kStaleMin || days > kStaleMax) {
        error_ = QStringLiteral("O prazo precisa estar entre %1 e %2 dias.").arg(kStaleMin).arg(kStaleMax);
        return false;
    }
    return write(QStringLiteral("updates.stale_after_days"), days);
}

bool SettingsPage::setSandboxTimeout(int seconds) {
    if (seconds < kTimeoutMin || seconds > kTimeoutMax) {
        error_ = QStringLiteral("O tempo precisa estar entre %1 e %2 segundos.").arg(kTimeoutMin).arg(kTimeoutMax);
        return false;
    }
    return write(QStringLiteral("sandbox.timeout_seconds"), seconds);
}

bool SettingsPage::setSysmonPath(const QString& path) {
    if (!path.isEmpty()) {
        // Same rule as gamekernel/sandbox/manager.py: an existing Sysmon64.exe or Sysmon.exe.
        const QFileInfo f(path);
        const QString name = f.fileName().toLower();
        if (!f.isFile() || (name != QLatin1String("sysmon64.exe") && name != QLatin1String("sysmon.exe"))) {
            error_ = QStringLiteral("Escolha o arquivo Sysmon64.exe (ou Sysmon.exe) da Microsoft Sysinternals.");
            return false;
        }
        return write(QStringLiteral("sandbox.sysmon_path"), f.absoluteFilePath());
    }
    return write(QStringLiteral("sandbox.sysmon_path"), QString());
}

bool SettingsPage::restoreDefaults() {
    if (!ctx_->ask(this, QStringLiteral("Restaurar padrões"),
                   QStringLiteral("Voltar as opções desta página aos valores padrão? A análise comportamental será "
                                  "desativada e o Sysmon configurado será esquecido (o arquivo não é apagado).")))
        return false;
    return setRedactUsername(kRedactUsername) && setIncludeHostname(kIncludeHostname) && setStaleAfterDays(kStaleDays) &&
           setSandboxEnabled(kSandboxEnabled) && setSandboxTimeout(kSandboxTimeout) && setSysmonPath(QString());
}

}  // namespace gk::app
