#include "settings_page.hpp"

#include "../ui_kit.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QThread>
#include <QUrl>

#include <algorithm>

namespace gk::app {

namespace {

// Defaults and ranges of gamekernel/config.py (the Python readers validate again).
constexpr bool kRedactUsername = true;
constexpr bool kIncludeHostname = false;
constexpr int kStaleDays = 7, kStaleMin = 1, kStaleMax = 365;
constexpr bool kSandboxEnabled = false;
constexpr int kSandboxTimeout = 120, kTimeoutMin = 30, kTimeoutMax = 1800;
constexpr int kMaxFileMb = 512, kArchiveDepth = 4, kArchiveTotalMb = 2048;

int defaultWorkers() { return std::max(1, std::min(6, QThread::idealThreadCount() - 1)); }   // config.py

Qt::CaseSensitivity pathCase() {
#ifdef _WIN32
    return Qt::CaseInsensitive;
#else
    return Qt::CaseSensitive;
#endif
}

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

    auto* scan = new Card(QStringLiteral("Varredura"), content);
    mode_ = new QComboBox(scan);
    mode_->addItem(QStringLiteral("Completa (todos os tipos, dentro de compactados)"), QStringLiteral("deep"));
    mode_->addItem(QStringLiteral("Rápida (executáveis e scripts)"), QStringLiteral("quick"));
    scan->body()->addLayout(labelled(QStringLiteral("Modo padrão da varredura:"), mode_, scan));
    workers_ = spin(1, 32, scan);
    scan->body()->addLayout(labelled(QStringLiteral("Processos de análise em paralelo:"), workers_, scan));
    maxFileMb_ = spin(8, 16384, scan);
    scan->body()->addLayout(labelled(QStringLiteral("Analisar por completo arquivos de até (MB):"), maxFileMb_, scan));
    archiveDepth_ = spin(0, 10, scan);
    scan->body()->addLayout(labelled(QStringLiteral("Compactados dentro de compactados, até o nível:"), archiveDepth_, scan));
    archiveTotalMb_ = spin(16, 65536, scan);
    scan->body()->addLayout(labelled(QStringLiteral("Descompactar no máximo, por compactado (MB):"), archiveTotalMb_, scan));
    clamav_ = new QCheckBox(QStringLiteral("Usar o ClamAV nas varreduras (quando instalado com o programa)"), scan);
    scan->body()->addWidget(clamav_);
    scan->body()->addWidget(new QLabel(QStringLiteral("Pastas excluídas da varredura e da proteção em tempo real:"), scan));
    excludedFolders_ = new QListWidget(scan);
    excludedFolders_->setMaximumHeight(110);
    scan->body()->addWidget(excludedFolders_);
    auto* exRow = new QHBoxLayout;
    auto* addExcluded = new QPushButton(icon(QStringLiteral("plus")), QStringLiteral("Excluir pasta…"), scan);
    removeExcluded_ = new QPushButton(icon(QStringLiteral("minus")), QStringLiteral("Remover"), scan);
    exRow->addWidget(addExcluded);
    exRow->addWidget(removeExcluded_);
    exRow->addStretch();
    scan->body()->addLayout(exRow);
    excludedExt_ = new QLineEdit(scan);
    excludedExt_->setPlaceholderText(QStringLiteral(".pak, .bk2"));
    scan->body()->addLayout(labelled(QStringLiteral("Extensões excluídas:"), excludedExt_, scan));
    scan->body()->addWidget(mutedLabel(QStringLiteral("Arquivos excluídos aparecem no resultado como \"excluído nas configurações\", "
                                                      "nunca somem em silêncio. Limites maiores analisam mais a fundo e demoram mais; "
                                                      "valem também para o gk-cli."),
                                       scan));
    col->addWidget(scan);

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
    col->addWidget(mutedLabel(QStringLiteral("As opções da proteção em tempo real ficam na página Tempo real."), content));
    col->addStretch();

    reload();
    connect(mode_, &QComboBox::currentIndexChanged, this, [this](int i) { setDefaultMode(mode_->itemData(i).toString()); });
    connect(workers_, &QSpinBox::valueChanged, this, &SettingsPage::setScanWorkers);
    connect(maxFileMb_, &QSpinBox::valueChanged, this, &SettingsPage::setMaxFileSizeMb);
    connect(archiveDepth_, &QSpinBox::valueChanged, this, &SettingsPage::setArchiveDepth);
    connect(archiveTotalMb_, &QSpinBox::valueChanged, this, &SettingsPage::setArchiveTotalMb);
    connect(clamav_, &QCheckBox::toggled, this, &SettingsPage::setClamavEnabled);
    connect(addExcluded, &QPushButton::clicked, this, [this] {
        const QString dir = QFileDialog::getExistingDirectory(this, QStringLiteral("Pasta a excluir"));
        if (!dir.isEmpty() && !addExcludedFolder(dir))
            emit ctx_->notify(AppContext::Level::Warning, QStringLiteral("Configurações"), error_);
    });
    connect(removeExcluded_, &QPushButton::clicked, this, [this] {
        if (auto* item = excludedFolders_->currentItem()) removeExcludedFolder(item->data(Qt::UserRole).toString());
    });
    connect(excludedFolders_, &QListWidget::currentRowChanged, this, [this](int row) { removeExcluded_->setEnabled(row >= 0); });
    connect(excludedExt_, &QLineEdit::editingFinished, this, [this] {
        if (!setExcludedExtensions(excludedExt_->text()))
            emit ctx_->notify(AppContext::Level::Warning, QStringLiteral("Configurações"), error_);
    });
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
    const QSignalBlocker s1(mode_), s2(workers_), s3(maxFileMb_), s4(archiveDepth_), s5(archiveTotalMb_), s6(clamav_),
        s7(excludedExt_);
    mode_->setCurrentIndex(ctx_->setting(QStringLiteral("scan.default_mode"), QStringLiteral("deep")).toString() == QLatin1String("quick") ? 1 : 0);
    workers_->setValue(ctx_->setting(QStringLiteral("scan.max_workers"), defaultWorkers()).toInt(defaultWorkers()));
    maxFileMb_->setValue(ctx_->setting(QStringLiteral("scan.max_file_size_mb"), kMaxFileMb).toInt(kMaxFileMb));
    archiveDepth_->setValue(ctx_->setting(QStringLiteral("scan.max_archive_depth"), kArchiveDepth).toInt(kArchiveDepth));
    archiveTotalMb_->setValue(ctx_->setting(QStringLiteral("scan.max_archive_total_mb"), kArchiveTotalMb).toInt(kArchiveTotalMb));
    clamav_->setChecked(ctx_->setting(QStringLiteral("engines.clamav.enabled"), true).toBool(true));
    excludedFolders_->clear();
    for (const auto& v : ctx_->setting(QStringLiteral("scan.excluded_paths")).toArray()) {
        auto* item = new QListWidgetItem(icon(QStringLiteral("folder")), QDir::toNativeSeparators(v.toString()), excludedFolders_);
        item->setData(Qt::UserRole, v.toString());
    }
    removeExcluded_->setEnabled(false);
    QStringList exts;
    for (const auto& v : ctx_->setting(QStringLiteral("scan.excluded_extensions")).toArray()) exts << v.toString();
    excludedExt_->setText(exts.join(QStringLiteral(", ")));

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

bool SettingsPage::setDefaultMode(const QString& mode) {
    if (mode != QLatin1String("deep") && mode != QLatin1String("quick")) {
        error_ = QStringLiteral("Modo de varredura inválido.");
        return false;
    }
    return write(QStringLiteral("scan.default_mode"), mode);
}

namespace {
bool inRange(int v, int lo, int hi, const QString& what, QString* error) {
    if (v >= lo && v <= hi) return true;
    *error = QStringLiteral("%1 precisa estar entre %2 e %3.").arg(what).arg(lo).arg(hi);
    return false;
}
}  // namespace

bool SettingsPage::setScanWorkers(int workers) {
    return inRange(workers, 1, 32, QStringLiteral("O número de processos"), &error_) && write(QStringLiteral("scan.max_workers"), workers);
}
bool SettingsPage::setMaxFileSizeMb(int mb) {
    return inRange(mb, 8, 16384, QStringLiteral("O tamanho máximo"), &error_) && write(QStringLiteral("scan.max_file_size_mb"), mb);
}
bool SettingsPage::setArchiveDepth(int depth) {
    return inRange(depth, 0, 10, QStringLiteral("O nível de compactados"), &error_) && write(QStringLiteral("scan.max_archive_depth"), depth);
}
bool SettingsPage::setArchiveTotalMb(int mb) {
    return inRange(mb, 16, 65536, QStringLiteral("O limite de descompactação"), &error_) &&
           write(QStringLiteral("scan.max_archive_total_mb"), mb);
}
bool SettingsPage::setClamavEnabled(bool on) { return write(QStringLiteral("engines.clamav.enabled"), on); }

bool SettingsPage::addExcludedFolder(const QString& folder) {
    const QFileInfo info(folder);
    if (folder.trimmed().isEmpty() || !info.isDir()) {
        error_ = QStringLiteral("A pasta não existe: %1").arg(QDir::toNativeSeparators(folder));
        return false;
    }
    const QString clean = QDir::cleanPath(info.absoluteFilePath());
    QJsonArray list = ctx_->setting(QStringLiteral("scan.excluded_paths")).toArray();
    for (const auto& v : list) {
        if (QDir::cleanPath(v.toString()).compare(clean, pathCase()) == 0) {
            error_ = QStringLiteral("Essa pasta já está excluída.");
            return false;
        }
    }
    list.append(clean);
    return write(QStringLiteral("scan.excluded_paths"), list);
}

bool SettingsPage::removeExcludedFolder(const QString& folder) {
    QJsonArray list;
    bool found = false;
    for (const auto& v : ctx_->setting(QStringLiteral("scan.excluded_paths")).toArray()) {
        if (v.toString() == folder) found = true;
        else list.append(v);
    }
    return found && write(QStringLiteral("scan.excluded_paths"), list);
}

bool SettingsPage::setExcludedExtensions(const QString& text) {
    // Same normalisation as config.py: ".ext", lower case, unique, sorted.
    QStringList exts;
    for (QString e : text.split(QRegularExpression(QStringLiteral("[,;\\s]+")), Qt::SkipEmptyParts)) {
        e = e.trimmed().toLower();
        while (e.startsWith('.')) e.remove(0, 1);
        if (e.isEmpty()) continue;
        if (!QRegularExpression(QStringLiteral("^[a-z0-9_\\-]{1,16}$")).match(e).hasMatch()) {
            error_ = QStringLiteral("Extensão inválida: %1").arg(e);
            reload();
            return false;
        }
        e.prepend('.');
        if (!exts.contains(e)) exts << e;
    }
    exts.sort();
    return write(QStringLiteral("scan.excluded_extensions"), QJsonArray::fromStringList(exts));
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
                   QStringLiteral("Voltar as opções desta página aos valores padrão? As exclusões da varredura serão "
                                  "esvaziadas, a análise comportamental será desativada e o Sysmon configurado será "
                                  "esquecido (o arquivo não é apagado).")))
        return false;
    return setDefaultMode(QStringLiteral("deep")) && setScanWorkers(defaultWorkers()) && setMaxFileSizeMb(kMaxFileMb) &&
           setArchiveDepth(kArchiveDepth) && setArchiveTotalMb(kArchiveTotalMb) && setClamavEnabled(true) &&
           write(QStringLiteral("scan.excluded_paths"), QJsonArray()) && setExcludedExtensions(QString()) &&
           setRedactUsername(kRedactUsername) && setIncludeHostname(kIncludeHostname) && setStaleAfterDays(kStaleDays) &&
           setSandboxEnabled(kSandboxEnabled) && setSandboxTimeout(kSandboxTimeout) && setSysmonPath(QString());
}

}  // namespace gk::app
