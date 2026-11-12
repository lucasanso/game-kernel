// Asynchronous Qt client for Game Kernel helper processes (gk-ipc v1).
//
// The application never embeds Python: Python services run in a separate process started and
// supervised by this class. A crash, hang or memory blow-up of the helper only fails the pending
// calls (helper_crashed / timeout); the application keeps running and the helper is restarted
// on the next call, up to HelperConfig::maxRestarts consecutive failures.
//
// Thread affinity: use a HelperClient from the thread that owns it (normally the UI thread). All
// operations are non-blocking; results arrive through signals. callBlocking() exists for tools
// and tests only and must not be used on the UI thread.
#pragma once

#include "gk/ipc/protocol.hpp"

#include <QDeadlineTimer>
#include <QJsonObject>
#include <QObject>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStringList>
#include <QTimer>

#include <map>
#include <memory>

namespace gk::ipc {

struct HelperConfig {
    QString program;                    // absolute path of gk-helper(.exe) or of the Python interpreter (dev)
    QStringList arguments;              // e.g. {"-I", "<repo>/gk_helper.py"} in development
    QString workingDirectory;           // the helper's own directory, never a scanned folder
    QProcessEnvironment environment;    // see sanitizedEnvironment()
    int helloTimeoutMs = 20000;
    int cancelGraceMs = 5000;           // after a timeout+cancel, kill the helper if it does not answer
    qint64 maxFrame = kDefaultMaxFrame;
    int maxRestarts = 3;                // consecutive failures before the helper is declared unavailable
    qint64 memoryLimitBytes = qint64(2) * 1024 * 1024 * 1024;   // 0 = unlimited (Job Object / RLIMIT_AS)

    // Frozen layout: <appDir>/helper/gk-helper(.exe).
    static HelperConfig forInstallation(const QString& appDir, const QString& dataDir);
    // Development layout: <python> -I <repoRoot>/gk_helper.py
    static HelperConfig forDevelopment(const QString& python, const QString& repoRoot, const QString& dataDir);
};

// Minimal environment for the helper: OS essentials + GAMEKERNEL_DATA_DIR. No PYTHON* variables,
// no proxies, nothing inherited by accident.
QProcessEnvironment sanitizedEnvironment(const QString& dataDir);

class HelperClient : public QObject {
    Q_OBJECT
public:
    enum class State { Stopped, Starting, Ready, Unavailable };
    Q_ENUM(State)

    struct Result {
        bool ok = false;
        QJsonValue value;
        CallError error;
    };

    explicit HelperClient(HelperConfig config, QObject* parent = nullptr);
    ~HelperClient() override;

    // Queue a call. Starts the helper if needed. Returns the request id used in the signals.
    qint64 call(const QString& method, const QJsonObject& params = {}, int timeoutMs = 60000);
    void cancel(qint64 id);
    // Close stdin (the helper exits on EOF), wait up to waitMs, then kill.
    void stop(int waitMs = 5000);

    // Blocking helper for tools and tests: spins a local event loop until the call completes.
    Result callBlocking(const QString& method, const QJsonObject& params = {}, int timeoutMs = 60000);

    State state() const { return state_; }
    QJsonObject hello() const { return hello_; }
    QStringList stderrTail() const { return stderrTail_; }
    int consecutiveFailures() const { return consecutiveFailures_; }
    qint64 processId() const;
    void resetFailures() { consecutiveFailures_ = 0; if (state_ == State::Unavailable) state_ = State::Stopped; }

signals:
    void ready(const QJsonObject& hello);
    void callSucceeded(qint64 id, const QJsonValue& result);
    void callFailed(qint64 id, const gk::ipc::CallError& error);
    void eventReceived(qint64 id, const QString& name, const QJsonObject& data);
    void logReceived(const QString& level, const QString& logger, const QString& message);
    void helperFinished(int exitCode, const QString& reason);
    void stateChanged(gk::ipc::HelperClient::State state);

private:
    struct Pending {
        QString method;
        QJsonObject params;
        int timeoutMs = 0;
        QDeadlineTimer deadline;
        QDeadlineTimer graceDeadline;
        bool sent = false;
        bool cancelSent = false;
        bool timedOut = false;
    };

    void startProcess();
    void setState(State s);
    void onStdout();
    void onStderr();
    void onFinished(int exitCode, QProcess::ExitStatus status);
    void onProcessError(QProcess::ProcessError error);
    void onTick();
    void flushQueue();
    void handleMessage(const QJsonObject& message);
    bool writeMessage(const QJsonObject& message);
    void protocolFailure(const QString& reason);
    void failAll(const char* code, const QString& reason);
    void failAllLater(const char* code, const QString& reason);
    // Kill the current process *now* and detach it, so new calls go to a fresh helper.
    void retire(const char* code, const QString& reason);
    void finish(qint64 id, bool ok, const QJsonValue& value, const CallError& error);
    void configurePlatform();

    HelperConfig config_;
    QProcess* process_ = nullptr;
    FrameDecoder decoder_;
    QTimer tick_;
    QTimer helloTimer_;
    std::map<qint64, Pending> pending_;
    qint64 nextId_ = 1;
    State state_ = State::Stopped;
    QJsonObject hello_;
    QStringList stderrTail_;
    QByteArray stderrBuffer_;
    QString exitReason_;
    int consecutiveFailures_ = 0;
    bool stopping_ = false;
    struct PlatformData;
    std::unique_ptr<PlatformData> platform_;
};

}  // namespace gk::ipc

Q_DECLARE_METATYPE(gk::ipc::CallError)
