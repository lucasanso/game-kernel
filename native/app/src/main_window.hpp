// Main window: sidebar navigation, page header, page stack and in-app notifications (toasts).
// Only pages backed by working services are listed; core pages (dashboard, scanner, results,
// quarantine, history, real-time, performance, optimizer) are added as native/bridge (Agent A) lands.
#pragma once

#include "app_context.hpp"

#include <QMainWindow>
#include <QStringList>

class QLabel;
class QListWidget;
class QStackedWidget;
class QVBoxLayout;

namespace gk::app {

class UpdatesPage;
class SandboxPage;
class PrivacyPage;

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
    UpdatesPage* updatesPage() const { return updates_; }
    SandboxPage* sandboxPage() const { return sandbox_; }
    PrivacyPage* privacyPage() const { return privacy_; }
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
    UpdatesPage* updates_ = nullptr;
    SandboxPage* sandbox_ = nullptr;
    PrivacyPage* privacy_ = nullptr;
};

}  // namespace gk::app
