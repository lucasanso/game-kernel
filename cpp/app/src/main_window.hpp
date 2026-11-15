// Main window: sidebar navigation, page header, page stack and in-app notifications (toasts).
// Only pages backed by working services are listed (real-time, performance and optimizer pages join with
// their core modules, M11/M12).
#pragma once

#include "app_context.hpp"

#include <QMainWindow>
#include <QStringList>

class QLabel;
class QListWidget;
class QStackedWidget;
class QVBoxLayout;

namespace gk::app {

class DashboardPage;
class ScanPage;
class ResultsPage;
class HistoryPage;
class QuarantinePage;
class UpdatesPage;
class SandboxPage;
class PrivacyPage;
class ReportsPage;
class SettingsPage;

class ToastArea : public QWidget {
    Q_OBJECT
public:
    explicit ToastArea(QWidget* parent);
    void show(AppContext::Level level, const QString& title, const QString& text, int msec = 6000);
    int visibleCount() const;
    const QStringList& history() const { return history_; }

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void reposition();
    QVBoxLayout* stack_;
    QStringList history_;
};

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(AppContext* ctx, QWidget* parent = nullptr);

    int pageCount() const;
    void showPage(int index);
    QString currentTitle() const;
    // Page indices, in sidebar order.
    enum Page { Dashboard, Scan, Results, History, Quarantine, Updates, Sandbox, Reports, Privacy, Settings };
    DashboardPage* dashboardPage() const { return dashboard_; }
    ScanPage* scanPage() const { return scan_; }
    ResultsPage* resultsPage() const { return results_; }
    HistoryPage* historyPage() const { return history_; }
    QuarantinePage* quarantinePage() const { return quarantine_; }
    UpdatesPage* updatesPage() const { return updates_; }
    SandboxPage* sandboxPage() const { return sandbox_; }
    PrivacyPage* privacyPage() const { return privacy_; }
    ReportsPage* reportsPage() const { return reports_; }
    SettingsPage* settingsPage() const { return settings_; }
    ToastArea* toasts() const { return toasts_; }

private:
    struct PageInfo { QString title; QString subtitle; };
    void addPage(QWidget* page, const QString& iconName, const QString& navLabel, const QString& title,
                 const QString& subtitle);

    AppContext* ctx_;
    QListWidget* nav_;
    QStackedWidget* stack_;
    QLabel* title_;
    QLabel* subtitle_;
    ToastArea* toasts_;
    QList<PageInfo> pages_;
    DashboardPage* dashboard_ = nullptr;
    ScanPage* scan_ = nullptr;
    ResultsPage* results_ = nullptr;
    HistoryPage* history_ = nullptr;
    QuarantinePage* quarantine_ = nullptr;
    UpdatesPage* updates_ = nullptr;
    SandboxPage* sandbox_ = nullptr;
    PrivacyPage* privacy_ = nullptr;
    ReportsPage* reports_ = nullptr;
    SettingsPage* settings_ = nullptr;
};

}  // namespace gk::app
