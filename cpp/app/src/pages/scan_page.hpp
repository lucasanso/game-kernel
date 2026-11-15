// "Segurança do jogo": choose game, crack, repack or mod folders/files and scan them with the core
// (gk::bridge::ScanService: isolated worker processes, nothing is executed). Live progress, live findings
// and, at the end, a link to the full forensic analysis of the scan.
#pragma once

#include "../app_context.hpp"

#include <QJsonObject>
#include <QWidget>

class QLabel;
class QListWidget;
class QProgressBar;
class QPushButton;
class QRadioButton;
class QTableWidget;

namespace gk::app {

class StatusPill;

class ScanPage : public QWidget {
    Q_OBJECT
public:
    explicit ScanPage(AppContext* ctx, QWidget* parent = nullptr);

    void addTarget(const QString& path);            // folder or file; duplicates are ignored
    void clearTargets();
    QStringList targets() const;
    void setDeep(bool deep);
    bool start();                                   // false without targets or while a scan runs
    void pause();
    void resume();
    void cancel();
    bool running() const;
    int findingsCount() const;                      // rows in "Achados"
    QJsonObject lastSummary() const { return summary_; }

signals:
    void scanFinished(const QJsonObject& summary);
    void openResults(qint64 scanId);

private:
    void onProgress(const QJsonObject& progress);
    void onFile(const QJsonObject& result);
    void onFinished(const QJsonObject& summary);
    void updateButtons();

    AppContext* ctx_;
    QJsonObject summary_;
    qint64 scanId_ = 0;
    bool paused_ = false;
    QListWidget* targets_;
    QRadioButton* deep_;
    QRadioButton* quick_;
    QPushButton* startButton_;
    QPushButton* pauseButton_;
    QPushButton* cancelButton_;
    QPushButton* removeButton_;
    QPushButton* resultsButton_;
    QLabel* phase_;
    QProgressBar* bar_;
    QLabel* current_;
    StatusPill* threats_;
    StatusPill* suspicious_;
    StatusPill* errors_;
    QTableWidget* findings_;
    QLabel* summaryLabel_;
};

}  // namespace gk::app
