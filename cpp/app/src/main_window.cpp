#include "main_window.hpp"

#include "pages/dashboard_page.hpp"
#include "pages/helper_pages.hpp"
#include "pages/history_page.hpp"
#include "pages/quarantine_page.hpp"
#include "pages/results_page.hpp"
#include "pages/scan_page.hpp"
#include "pages/reports_page.hpp"
#include "pages/settings_page.hpp"
#include "pages/updates_page.hpp"
#include "ui_kit.hpp"

#include <QEvent>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPointer>
#include <QStackedWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace gk::app {

// ============================================================================================ toasts
ToastArea::ToastArea(QWidget* parent) : QWidget(parent) {
    setAttribute(Qt::WA_TransparentForMouseEvents, false);
    stack_ = new QVBoxLayout(this);
    stack_->setContentsMargins(0, 0, 0, 0);
    stack_->setSpacing(8);
    stack_->addStretch();
    parent->installEventFilter(this);
    reposition();
}

int ToastArea::visibleCount() const { return stack_->count() - 1; }

void ToastArea::show(AppContext::Level level, const QString& title, const QString& text, int msec) {
    history_ << QStringLiteral("%1: %2").arg(title, text);
    auto* toast = new QFrame(this);
    toast->setObjectName(QStringLiteral("toast"));
    toast->setFixedWidth(360);
    auto* row = new QHBoxLayout(toast);
    row->setContentsMargins(14, 12, 14, 12);
    QString iconName = QStringLiteral("info");
    QColor color = palette::Accent;
    switch (level) {
        case AppContext::Level::Success: iconName = QStringLiteral("check"); color = palette::Success; break;
        case AppContext::Level::Warning: iconName = QStringLiteral("alert"); color = palette::Medium; break;
        case AppContext::Level::Error: iconName = QStringLiteral("alert"); color = palette::Critical; break;
        case AppContext::Level::Info: break;
    }
    auto* iconLabel = new QLabel(toast);
    iconLabel->setPixmap(icon(iconName, color, 20).pixmap(20, 20));
    row->addWidget(iconLabel, 0, Qt::AlignTop);
    auto* texts = new QVBoxLayout;
    auto* t = new QLabel(QStringLiteral("<b>%1</b>").arg(title.toHtmlEscaped()), toast);
    auto* b = new QLabel(text, toast);
    b->setWordWrap(true);
    b->setProperty("muted", true);
    texts->addWidget(t);
    texts->addWidget(b);
    row->addLayout(texts, 1);
    toast->setStyleSheet(QStringLiteral("QFrame#toast { border-left: 3px solid %1; }").arg(color.name()));
    stack_->addWidget(toast);
    while (stack_->count() - 1 > 4) {   // keep at most 4 on screen
        QLayoutItem* oldest = stack_->takeAt(1);
        delete oldest->widget();
        delete oldest;
    }
    reposition();
    raise();
    QPointer<QFrame> guard(toast);
    QTimer::singleShot(msec, this, [this, guard] {
        if (!guard) return;
        stack_->removeWidget(guard);
        guard->deleteLater();
        reposition();
    });
}

bool ToastArea::eventFilter(QObject* watched, QEvent* event) {
    if (watched == parentWidget() && event->type() == QEvent::Resize) reposition();
    return QWidget::eventFilter(watched, event);
}

void ToastArea::reposition() {
    if (!parentWidget()) return;
    const int width = 380;
    const int height = qMin(parentWidget()->height() - 40, 4 * 110);
    setGeometry(parentWidget()->width() - width - 20, parentWidget()->height() - height - 20, width, height);
}

// ============================================================================================ window
MainWindow::MainWindow(AppContext* ctx, QWidget* parent) : QMainWindow(parent), ctx_(ctx) {
    setWindowTitle(AppContext::productName());
    setWindowIcon(appIcon());
    resize(1200, 780);
    setMinimumSize(960, 640);

    auto* central = new QWidget(this);
    central->setObjectName(QStringLiteral("page"));
    auto* root = new QHBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // ---- sidebar
    auto* sidebar = new QWidget(central);
    sidebar->setObjectName(QStringLiteral("sidebar"));
    sidebar->setFixedWidth(250);
    auto* side = new QVBoxLayout(sidebar);
    side->setContentsMargins(12, 18, 12, 16);
    side->setSpacing(10);
    auto* brandRow = new QHBoxLayout;
    auto* logo = new QLabel(sidebar);
    logo->setPixmap(appIcon().pixmap(38, 38));
    auto* brandText = new QVBoxLayout;
    auto* brand = new QLabel(AppContext::productName(), sidebar);
    brand->setObjectName(QStringLiteral("brand"));
    auto* version = new QLabel(QStringLiteral("versão %1").arg(AppContext::appVersion()), sidebar);
    version->setObjectName(QStringLiteral("version"));
    brandText->addWidget(brand);
    brandText->addWidget(version);
    brandRow->addWidget(logo);
    brandRow->addLayout(brandText, 1);
    side->addLayout(brandRow);
    side->addSpacing(12);
    nav_ = new QListWidget(sidebar);
    nav_->setObjectName(QStringLiteral("nav"));
    nav_->setIconSize(QSize(20, 20));
    side->addWidget(nav_, 1);
    auto* offline = new StatusPill(QStringLiteral("100% offline"), StatusPill::Tone::Good, sidebar);
    offline->setToolTip(QStringLiteral("Nenhum componente do Game Kernel usa a internet."));
    side->addWidget(offline, 0, Qt::AlignLeft);
    root->addWidget(sidebar);

    // ---- content
    auto* contentArea = new QWidget(central);
    contentArea->setObjectName(QStringLiteral("page"));
    auto* content = new QVBoxLayout(contentArea);
    content->setContentsMargins(28, 22, 20, 16);
    content->setSpacing(4);
    title_ = new QLabel(contentArea);
    title_->setObjectName(QStringLiteral("pageTitle"));
    subtitle_ = new QLabel(contentArea);
    subtitle_->setObjectName(QStringLiteral("pageSubtitle"));
    subtitle_->setWordWrap(true);
    content->addWidget(title_);
    content->addWidget(subtitle_);
    content->addSpacing(14);
    stack_ = new QStackedWidget(contentArea);
    content->addWidget(stack_, 1);
    root->addWidget(contentArea, 1);
    setCentralWidget(central);

    dashboard_ = new DashboardPage(ctx_, stack_);
    scan_ = new ScanPage(ctx_, stack_);
    results_ = new ResultsPage(ctx_, stack_);
    history_ = new HistoryPage(ctx_, stack_);
    quarantine_ = new QuarantinePage(ctx_, stack_);
    updates_ = new UpdatesPage(ctx_, stack_);
    sandbox_ = new SandboxPage(ctx_, stack_);
    reports_ = new ReportsPage(ctx_, stack_);
    privacy_ = new PrivacyPage(ctx_, stack_);
    settings_ = new SettingsPage(ctx_, stack_);
    addPage(dashboard_, QStringLiteral("home"), QStringLiteral("Painel"), QStringLiteral("Painel"),
            QStringLiteral("A situação da proteção deste computador, sem nada sair dele."));
    addPage(scan_, QStringLiteral("search"), QStringLiteral("Segurança do jogo"), QStringLiteral("Segurança do jogo"),
            QStringLiteral("Analise a pasta de um jogo, crack, repack ou mod. Nada é executado."));
    addPage(results_, QStringLiteral("file-search"), QStringLiteral("Análise forense"), QStringLiteral("Análise forense"),
            QStringLiteral("O que foi encontrado, onde, por que é suspeito e o que fazer."));
    addPage(history_, QStringLiteral("clock"), QStringLiteral("Histórico"), QStringLiteral("Histórico"),
            QStringLiteral("Todas as varreduras feitas neste computador."));
    addPage(quarantine_, QStringLiteral("archive"), QStringLiteral("Quarentena"), QStringLiteral("Quarentena"),
            QStringLiteral("Arquivos isolados num cofre criptografado; restaure ou apague quando quiser."));
    addPage(updates_, QStringLiteral("package"), QStringLiteral("Atualização offline"), QStringLiteral("Central de Atualização Offline"),
            QStringLiteral("Importe pacotes assinados de assinaturas, regras e indicadores. Nada é baixado."));
    addPage(sandbox_, QStringLiteral("flask"), QStringLiteral("Análise comportamental"), QStringLiteral("Análise comportamental"),
            QStringLiteral("Observe o comportamento de um arquivo dentro de uma máquina virtual descartável e sem rede."));
    addPage(reports_, QStringLiteral("file-text"), QStringLiteral("Relatórios"), QStringLiteral("Relatórios forenses"),
            QStringLiteral("Gere relatórios em HTML, JSON ou PDF das varreduras registradas neste computador."));
    addPage(privacy_, QStringLiteral("lock"), QStringLiteral("Privacidade e rede"), QStringLiteral("Privacidade e rede"),
            QStringLiteral("Confira que o Game Kernel funciona offline e o que fica armazenado neste computador."));
    addPage(settings_, QStringLiteral("sliders"), QStringLiteral("Configurações"), QStringLiteral("Configurações"),
            QStringLiteral("Padrões dos relatórios, aviso de atualização e análise comportamental."));

    toasts_ = new ToastArea(centralWidget());
    connect(ctx_, &AppContext::notify, this, [this](AppContext::Level level, const QString& title, const QString& text) {
        toasts_->show(level, title, text);
    });
    connect(nav_, &QListWidget::currentRowChanged, this, &MainWindow::showPage);

    // Navigation between pages.
    auto openResults = [this](qint64 scanId) {
        results_->loadScan(scanId);
        showPage(Results);
    };
    auto openReports = [this](qint64 scanId) {
        reports_->focusScan(scanId);
        showPage(Reports);
    };
    connect(dashboard_, &DashboardPage::requestScan, this, [this](const QString& folder) {
        if (scan_->running()) {
            showPage(Scan);
            return;
        }
        scan_->clearTargets();
        scan_->addTarget(folder);
        scan_->start();
        showPage(Scan);
    });
    connect(dashboard_, &DashboardPage::openResults, this, openResults);
    connect(dashboard_, &DashboardPage::openUpdates, this, [this] { showPage(Updates); });
    connect(dashboard_, &DashboardPage::openQuarantine, this, [this] { showPage(Quarantine); });
    connect(dashboard_, &DashboardPage::openHistory, this, [this] { showPage(History); });
    connect(scan_, &ScanPage::openResults, this, openResults);
    connect(scan_, &ScanPage::scanFinished, this, [this] {
        history_->refresh();
        dashboard_->refresh();
        reports_->refresh();
    });
    connect(history_, &HistoryPage::openResults, this, openResults);
    connect(history_, &HistoryPage::openReports, this, openReports);
    connect(results_, &ResultsPage::openReports, this, openReports);
    connect(results_, &ResultsPage::quarantineFinished, this, [this] {
        quarantine_->refresh();
        dashboard_->refresh();
    });
    connect(quarantine_, &QuarantinePage::operationFinished, this, [this] { dashboard_->refresh(); });
    results_->loadLatest();
    nav_->setCurrentRow(0);
}

void MainWindow::addPage(QWidget* page, const QString& iconName, const QString& navLabel, const QString& title,
                         const QString& subtitle) {
    stack_->addWidget(page);
    auto* item = new QListWidgetItem(icon(iconName, palette::Muted), navLabel, nav_);
    item->setSizeHint(QSize(0, 42));
    pages_.append({title, subtitle});
}

int MainWindow::pageCount() const { return stack_->count(); }

void MainWindow::showPage(int index) {
    if (index < 0 || index >= stack_->count()) return;
    if (nav_->currentRow() != index) nav_->setCurrentRow(index);
    stack_->setCurrentIndex(index);
    title_->setText(pages_[index].title);
    subtitle_->setText(pages_[index].subtitle);
}

QString MainWindow::currentTitle() const { return title_->text(); }

}  // namespace gk::app
