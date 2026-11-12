// Pages backed by the Python helper process (gk-ipc v1): behavioural analysis in Windows Sandbox
// and the privacy/offline status. All calls are asynchronous (HelperClient signals).
#pragma once

#include "../app_context.hpp"

#include <QJsonObject>
#include <QWidget>

class QCheckBox;
class QLabel;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QTableWidget;

namespace gk::app {

class StatusPill;

class SandboxPage : public QWidget {
    Q_OBJECT
public:
    explicit SandboxPage(AppContext* ctx, QWidget* parent = nullptr);

    void checkAvailability();
    void setSample(const QString& path);
    void analyze();                       // asks for confirmation first
    void cancel();
    bool available() const { return available_; }
    bool canAnalyze() const;
    QString availabilityReason() const { return reason_; }

signals:
    void availabilityChecked(bool available);
    void analysisFinished(bool ok, const QString& message);

private:
    void onSucceeded(qint64 id, const QJsonValue& result);
    void onFailed(qint64 id, const gk::ipc::CallError& error);
    void onEvent(qint64 id, const QString& name, const QJsonObject& data);
    void showReport(const QJsonObject& report);
    void updateButtons();

    AppContext* ctx_;
    qint64 availabilityCall_ = -1;
    qint64 analyzeCall_ = -1;
    bool available_ = false;
    QString reason_;
    QString sample_;
    StatusPill* pill_;
    QLabel* reasonLabel_;
    QCheckBox* enable_;
    QLabel* sampleLabel_;
    QSpinBox* timeout_;
    QPushButton* analyzeButton_;
    QPushButton* cancelButton_;
    QProgressBar* progress_;
    QLabel* status_;
    QTableWidget* evidences_;
    QLabel* limitations_;
};

class PrivacyPage : public QWidget {
    Q_OBJECT
public:
    explicit PrivacyPage(AppContext* ctx, QWidget* parent = nullptr);

    void checkHelper();
    void runNetworkSelfTest();
    void restartHelper();
    QString lastSelfTestVerdict() const { return verdict_; }   // "ok", "falha" or empty

signals:
    void helperChecked(bool ok);
    void selfTestFinished(bool ok);

private:
    void onSucceeded(qint64 id, const QJsonValue& result);
    void onFailed(qint64 id, const gk::ipc::CallError& error);

    AppContext* ctx_;
    qint64 infoCall_ = -1;
    qint64 selfTestCall_ = -1;
    QString verdict_;
    StatusPill* helperPill_;
    QLabel* helperDetails_;
    StatusPill* netPill_;
    QLabel* netDetails_;
    QTableWidget* attempts_;
};

}  // namespace gk::app
