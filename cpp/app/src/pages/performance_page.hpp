// "Desempenho": what the computer is spending right now (gk::bridge::PerformanceService) — processor, memory,
// video card and video memory, disk — with the last minute drawn, and the programs that use the most. Samples
// are taken only while the page is on screen. Measurements come from Windows itself; nothing is changed.
#pragma once

#include "../app_context.hpp"

#include <QJsonObject>
#include <QWidget>

class QComboBox;
class QLabel;
class QTableWidget;

namespace gk::app {

class Sparkline;

class PerformancePage : public QWidget {
    Q_OBJECT
public:
    explicit PerformancePage(AppContext* ctx, QWidget* parent = nullptr);
    void setSampling(bool on);        // also follows the page being shown or hidden
    [[nodiscard]] bool sampling() const { return sampling_; }
    [[nodiscard]] int sampleCount() const { return samples_; }
    [[nodiscard]] QString cpuText() const;
    [[nodiscard]] QString memoryText() const;
    [[nodiscard]] QString gpuText() const;
    [[nodiscard]] QString diskText() const;
    [[nodiscard]] QString notesText() const;
    [[nodiscard]] int processRows() const;
    [[nodiscard]] QString processesEmptyText() const;   // shown instead of an empty table
    void sortProcessesBy(const QString& key);   // cpu | memory | gpu

signals:
    void updated(const QJsonObject& sample);

protected:
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;

private:
    void display(const QJsonObject& sample);
    void fillProcesses();

    AppContext* ctx_;
    bool sampling_ = false;
    int samples_ = 0;
    QJsonObject last_;
    QLabel* cpuValue_;
    QLabel* cpuSub_;
    Sparkline* cpuLine_;
    QLabel* memValue_;
    QLabel* memSub_;
    Sparkline* memLine_;
    QLabel* gpuValue_;
    QLabel* gpuSub_;
    Sparkline* gpuLine_;
    QLabel* diskValue_;
    QLabel* diskSub_;
    Sparkline* diskLine_;
    QComboBox* sortBy_;
    QTableWidget* table_;
    QLabel* empty_;
    QLabel* notes_;
};

}  // namespace gk::app
