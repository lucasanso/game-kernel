// "Otimizador": read-only diagnostics of what affects games on this computer, each with what to do in Windows
// itself, and the clean-up of old temporary files in two steps (analyse, then delete exactly that after the
// user confirms). The program never changes a Windows setting (gk::bridge::OptimizerService).
#pragma once

#include "../app_context.hpp"

#include <QJsonArray>
#include <QJsonObject>
#include <QWidget>

class QLabel;
class QPushButton;
class QVBoxLayout;

namespace gk::app {

class OptimizerPage : public QWidget {
    Q_OBJECT
public:
    explicit OptimizerPage(AppContext* ctx, QWidget* parent = nullptr);
    void refreshDiagnostics();
    void analyzeTemp();
    bool cleanTemp();                                   // asks first; needs a fresh analysis
    [[nodiscard]] int checkCount() const { return checks_.size(); }
    [[nodiscard]] QString checkStatus(const QString& id) const;   // ok | attention | info | unavailable ("" = absent)
    [[nodiscard]] QString diagnosticsSummary() const;
    [[nodiscard]] QString tempText() const;
    [[nodiscard]] bool canClean() const;

signals:
    void diagnosed(int count);
    void tempAnalyzed(const QJsonObject& summary);
    void tempCleaned(const QJsonObject& result);

private:
    void showChecks(const QJsonArray& checks);

    AppContext* ctx_;
    qint64 diagRequest_ = -1;
    qint64 tempRequest_ = -1;
    QJsonArray checks_;
    QJsonObject plan_;
    QLabel* summary_;
    QVBoxLayout* checkList_;
    QPushButton* recheck_;
    QLabel* tempInfo_;
    QLabel* tempStatus_;
    QPushButton* analyze_;
    QPushButton* clean_;
};

}  // namespace gk::app
