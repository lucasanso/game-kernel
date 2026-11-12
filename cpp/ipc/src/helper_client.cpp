#include "gk/ipc/helper_client.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QEventLoop>
#include <QFileInfo>
#include <QJsonArray>

#include <vector>

#if defined(Q_OS_WIN)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#elif defined(Q_OS_UNIX)
#  include <sys/resource.h>
#  include <csignal>
#  if defined(Q_OS_LINUX)
#    include <sys/prctl.h>
#  endif
#endif

namespace gk::ipc {

namespace {
constexpr int kTickMs = 50;
constexpr int kStderrTailLines = 50;

const char* const kEnvWhitelist[] = {
    "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOME", "PATH", "LANG",
    "LC_ALL", "COMSPEC", "PATHEXT", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
};
}  // namespace

// ------------------------------------------------------------------------------------ config
QProcessEnvironment sanitizedEnvironment(const QString& dataDir) {
    const QProcessEnvironment system = QProcessEnvironment::systemEnvironment();
    QProcessEnvironment env;
    for (const QString& key : system.keys()) {
        for (const char* allowed : kEnvWhitelist) {
            if (key.compare(QLatin1String(allowed), Qt::CaseInsensitive) == 0) {
                env.insert(key, system.value(key));
                break;
            }
        }
    }
    env.insert(QStringLiteral("GAMEKERNEL_DATA_DIR"), QDir::toNativeSeparators(dataDir));
    env.insert(QStringLiteral("PYTHONIOENCODING"), QStringLiteral("utf-8"));
    env.insert(QStringLiteral("PYTHONDONTWRITEBYTECODE"), QStringLiteral("1"));
    return env;
}

HelperConfig HelperConfig::forInstallation(const QString& appDir, const QString& dataDir) {
    HelperConfig c;
    const QString helperDir = QDir(appDir).filePath(QStringLiteral("helper"));
#if defined(Q_OS_WIN)
    c.program = QDir(helperDir).filePath(QStringLiteral("gk-helper.exe"));
#else
    c.program = QDir(helperDir).filePath(QStringLiteral("gk-helper"));
#endif
    c.workingDirectory = helperDir;
    c.environment = sanitizedEnvironment(dataDir);
    return c;
}

HelperConfig HelperConfig::forDevelopment(const QString& python, const QString& repoRoot, const QString& dataDir) {
    HelperConfig c;
    c.program = python;
    c.arguments = {QStringLiteral("-I"), QDir(repoRoot).filePath(QStringLiteral("gamekernel/helper/entry.py"))};
    c.workingDirectory = repoRoot;
    c.environment = sanitizedEnvironment(dataDir);
    return c;
}

// ------------------------------------------------------------------------------------ platform
struct HelperClient::PlatformData {
#if defined(Q_OS_WIN)
    HANDLE job = nullptr;
    STARTUPINFOEXW startupInfo{};
    std::vector<unsigned char> attributeList;
    ~PlatformData() {
        if (startupInfo.lpAttributeList) DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
        if (job) CloseHandle(job);   // KILL_ON_JOB_CLOSE: the helper never outlives the application
    }
#endif
};

void HelperClient::configurePlatform() {
#if defined(Q_OS_WIN)
    // Job Object: the helper is killed when the application exits (even on a crash of the app),
    // gets a memory ceiling and no access to clipboard/desktop/system settings.
    if (!platform_->job) {
        platform_->job = CreateJobObjectW(nullptr, nullptr);
        if (platform_->job) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            if (config_.memoryLimitBytes > 0) {
                limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
                limits.ProcessMemoryLimit = SIZE_T(config_.memoryLimitBytes);
            }
            SetInformationJobObject(platform_->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
            JOBOBJECT_BASIC_UI_RESTRICTIONS ui{};
            ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
                                     JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
                                     JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
                                     JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
            SetInformationJobObject(platform_->job, JobObjectBasicUIRestrictions, &ui, sizeof(ui));
        }
    }
    PlatformData* pd = platform_.get();
    process_->setCreateProcessArgumentsModifier([pd](QProcess::CreateProcessArguments* args) {
        args->flags |= CREATE_NO_WINDOW;
        if (!pd->job) return;
        // Put the process in the job at creation time (PROC_THREAD_ATTRIBUTE_JOB_LIST, Windows 10+),
        // so there is no window in which it runs outside the job.
        SIZE_T size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        pd->attributeList.assign(size, 0);
        auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(pd->attributeList.data());
        if (!InitializeProcThreadAttributeList(list, 1, 0, &size)) return;
        if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST, &pd->job, sizeof(HANDLE), nullptr,
                                       nullptr)) {
            DeleteProcThreadAttributeList(list);
            return;
        }
        pd->startupInfo = STARTUPINFOEXW{};
        pd->startupInfo.StartupInfo = *args->startupInfo;          // keeps the std handles set by Qt
        pd->startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEXW);
        pd->startupInfo.lpAttributeList = list;
        args->startupInfo = &pd->startupInfo.StartupInfo;
        args->flags |= EXTENDED_STARTUPINFO_PRESENT;
    });
#elif defined(Q_OS_UNIX)
    const qint64 limit = config_.memoryLimitBytes;
    process_->setChildProcessModifier([limit]() {
        // Runs in the child between fork and exec: only async-signal-safe calls.
        if (limit > 0) {
            struct rlimit rl;
            rl.rlim_cur = rl.rlim_max = rlim_t(limit);
            setrlimit(RLIMIT_AS, &rl);
        }
#  if defined(Q_OS_LINUX)
        prctl(PR_SET_PDEATHSIG, SIGKILL);   // the helper dies with the application
#  endif
    });
#endif
}

// ------------------------------------------------------------------------------------ client
HelperClient::HelperClient(HelperConfig config, QObject* parent)
    : QObject(parent), config_(std::move(config)), decoder_(config_.maxFrame),
      platform_(std::make_unique<PlatformData>()) {
    qRegisterMetaType<gk::ipc::CallError>("gk::ipc::CallError");
    tick_.setInterval(kTickMs);
    connect(&tick_, &QTimer::timeout, this, &HelperClient::onTick);
    helloTimer_.setSingleShot(true);
    connect(&helloTimer_, &QTimer::timeout, this, [this] {
        retire(reason::HelperUnavailable, QStringLiteral("o processo auxiliar não respondeu ao handshake em %1 ms")
                                                  .arg(config_.helloTimeoutMs));
    });
}

HelperClient::~HelperClient() {
    if (process_) {
        process_->disconnect(this);
        if (process_->state() != QProcess::NotRunning) {
            process_->closeWriteChannel();
            if (!process_->waitForFinished(2000)) {
                process_->kill();
                process_->waitForFinished(2000);
            }
        }
    }
}

qint64 HelperClient::processId() const { return process_ ? process_->processId() : 0; }

void HelperClient::setState(State s) {
    if (state_ == s) return;
    state_ = s;
    emit stateChanged(s);
}

void HelperClient::startProcess() {
    if (consecutiveFailures_ >= config_.maxRestarts) {
        setState(State::Unavailable);
        return;
    }
    if (!QFileInfo(config_.program).isAbsolute()) {
        exitReason_ = QStringLiteral("caminho do processo auxiliar não é absoluto: %1").arg(config_.program);
        consecutiveFailures_ = config_.maxRestarts;   // configuration error: retrying cannot help
        setState(State::Unavailable);
        failAllLater(reason::HelperUnavailable, exitReason_);
        return;
    }
    if (process_) {
        process_->disconnect(this);
        process_->deleteLater();
    }
    decoder_ = FrameDecoder(config_.maxFrame);
    hello_ = {};
    exitReason_.clear();
    stderrBuffer_.clear();
    stopping_ = false;

    process_ = new QProcess(this);
    process_->setProgram(config_.program);
    process_->setArguments(config_.arguments);
    process_->setWorkingDirectory(config_.workingDirectory);
    process_->setProcessEnvironment(config_.environment);
    process_->setProcessChannelMode(QProcess::SeparateChannels);
    configurePlatform();
    connect(process_, &QProcess::readyReadStandardOutput, this, &HelperClient::onStdout);
    connect(process_, &QProcess::readyReadStandardError, this, &HelperClient::onStderr);
    connect(process_, &QProcess::finished, this, &HelperClient::onFinished);
    connect(process_, &QProcess::errorOccurred, this, &HelperClient::onProcessError);

    setState(State::Starting);
    helloTimer_.start(config_.helloTimeoutMs);
    tick_.start();
    process_->start(QIODevice::ReadWrite);
}

qint64 HelperClient::call(const QString& method, const QJsonObject& params, int timeoutMs) {
    const qint64 id = nextId_++;
    Pending p;
    p.method = method;
    p.params = params;
    p.timeoutMs = timeoutMs;
    pending_.emplace(id, std::move(p));

    if (state_ == State::Unavailable) {
        QMetaObject::invokeMethod(this, [this, id] {
            finish(id, false, {}, CallError::make(reason::HelperUnavailable,
                                                  QStringLiteral("processo auxiliar indisponível após %1 falhas "
                                                                 "seguidas: %2")
                                                      .arg(consecutiveFailures_).arg(exitReason_)));
        }, Qt::QueuedConnection);
        return id;
    }
    if (!tick_.isActive()) tick_.start();
    if (state_ == State::Stopped) startProcess();
    else if (state_ == State::Ready) flushQueue();
    return id;
}

void HelperClient::cancel(qint64 id) {
    auto it = pending_.find(id);
    if (it == pending_.end()) return;
    if (!it->second.sent) {
        finish(id, false, {}, CallError::make(reason::Cancelled, QStringLiteral("cancelado antes do envio")));
        return;
    }
    if (!it->second.cancelSent) {
        writeMessage(makeCancel(id));
        it->second.cancelSent = true;
        it->second.graceDeadline = QDeadlineTimer(config_.cancelGraceMs);
    }
}

void HelperClient::stop(int waitMs) {
    if (!process_ || process_->state() == QProcess::NotRunning) return;
    stopping_ = true;
    process_->closeWriteChannel();
    if (!process_->waitForFinished(waitMs)) {
        process_->kill();
        process_->waitForFinished(2000);
    }
}

HelperClient::Result HelperClient::callBlocking(const QString& method, const QJsonObject& params, int timeoutMs) {
    Result result;
    QEventLoop loop;
    qint64 wanted = -1;
    bool done = false;
    auto okConn = connect(this, &HelperClient::callSucceeded, &loop, [&](qint64 id, const QJsonValue& value) {
        if (id != wanted) return;
        result.ok = true;
        result.value = value;
        done = true;
        loop.quit();
    });
    auto errConn = connect(this, &HelperClient::callFailed, &loop, [&](qint64 id, const CallError& error) {
        if (id != wanted) return;
        result.ok = false;
        result.error = error;
        done = true;
        loop.quit();
    });
    wanted = call(method, params, timeoutMs);
    if (!done) loop.exec();
    disconnect(okConn);
    disconnect(errConn);
    return result;
}

bool HelperClient::writeMessage(const QJsonObject& message) {
    if (!process_ || process_->state() != QProcess::Running) return false;
    const auto frame = encodeFrame(message, config_.maxFrame);
    if (!frame) return false;
    return process_->write(*frame) == frame->size();
}

void HelperClient::flushQueue() {
    for (auto& [id, p] : pending_) {
        if (p.sent) continue;
        const QJsonObject request = makeRequest(id, p.method, p.params, p.timeoutMs);
        if (!encodeFrame(request, config_.maxFrame)) {
            // Too large to send: fail this call only.
            const qint64 failedId = id;
            QMetaObject::invokeMethod(this, [this, failedId] {
                finish(failedId, false, {}, CallError::make(reason::ResourceLimit,
                                                            QStringLiteral("requisição excede o tamanho máximo")));
            }, Qt::QueuedConnection);
            p.sent = true;
            continue;
        }
        writeMessage(request);
        p.sent = true;
        p.deadline = p.timeoutMs > 0 ? QDeadlineTimer(p.timeoutMs) : QDeadlineTimer(QDeadlineTimer::Forever);
    }
}

void HelperClient::onStdout() {
    decoder_.feed(process_->readAllStandardOutput());
    while (decoder_.hasMessage()) handleMessage(decoder_.takeMessage());
    if (decoder_.failed()) protocolFailure(decoder_.error());
}

void HelperClient::onStderr() {
    stderrBuffer_.append(process_->readAllStandardError());
    qsizetype nl;
    while ((nl = stderrBuffer_.indexOf('\n')) >= 0) {
        const QString line = QString::fromUtf8(stderrBuffer_.left(nl)).trimmed();
        stderrBuffer_.remove(0, nl + 1);
        if (line.isEmpty()) continue;
        stderrTail_.append(line);
        while (stderrTail_.size() > kStderrTailLines) stderrTail_.removeFirst();
        emit logReceived(QStringLiteral("WARNING"), QStringLiteral("helper.stderr"), line);
    }
    if (stderrBuffer_.size() > 64 * 1024) stderrBuffer_.clear();   // unbounded line: drop it
}

void HelperClient::protocolFailure(const QString& reason) {
    retire(reason::HelperCrashed, QStringLiteral("erro de protocolo vindo do processo auxiliar: %1").arg(reason));
}

void HelperClient::retire(const char* code, const QString& reason) {
    helloTimer_.stop();
    if (process_) {
        QProcess* old = process_;
        process_ = nullptr;
        old->disconnect(this);
        connect(old, &QProcess::finished, old, &QObject::deleteLater);
        old->kill();
        exitReason_ = reason;
        ++consecutiveFailures_;
        setState(consecutiveFailures_ >= config_.maxRestarts ? State::Unavailable : State::Stopped);
        emit helperFinished(-1, reason);
    }
    failAllLater(code, reason);
}

void HelperClient::failAllLater(const char* code, const QString& reason) {
    // Fail exactly the calls pending *now*; calls made afterwards go to the next helper.
    std::vector<qint64> ids;
    for (const auto& [id, p] : pending_) ids.push_back(id);
    const QByteArray r(code);
    QMetaObject::invokeMethod(this, [this, ids, r, reason] {
        for (qint64 id : ids) finish(id, false, {}, CallError::make(r.constData(), reason));
    }, Qt::QueuedConnection);
}

void HelperClient::handleMessage(const QJsonObject& m) {
    const QString kind = kindOf(m);
    if (kind == "hello") {
        if (state_ != State::Starting) return protocolFailure(QStringLiteral("hello repetido"));
        if (m.value("protocol").toInt() != kProtocolVersion)
            return protocolFailure(QStringLiteral("versão de protocolo do processo auxiliar incompatível: %1")
                                       .arg(m.value("protocol").toInt()));
        helloTimer_.stop();
        hello_ = m;
        setState(State::Ready);
        emit ready(hello_);
        flushQueue();
    } else if (kind == "event" && m.value("name").toString() == "log") {
        const QJsonObject d = m.value("data").toObject();
        emit logReceived(d.value("level").toString(), d.value("logger").toString(), d.value("message").toString());
    } else if (kind == "event") {
        // The contract does not require an id on events; the helper adds it (extension). Without
        // it, an event can only be attributed when exactly one call is in flight.
        qint64 id = -1;
        if (m.contains("id")) id = qint64(m.value("id").toDouble());
        else if (pending_.size() == 1) id = pending_.begin()->first;
        if (pending_.count(id)) emit eventReceived(id, m.value("name").toString(), m.value("data").toObject());
    } else if (kind == "response") {
        const qint64 id = qint64(m.value("id").toDouble());
        auto it = pending_.find(id);
        if (it == pending_.end()) return;   // late answer to a call already resolved locally
        if (m.contains("result")) {
            finish(id, true, m.value("result"), {});
        } else {
            CallError e = CallError::fromJson(m.value("error").toObject());
            if (it->second.timedOut && (e.reason == QLatin1String(reason::Cancelled) ||
                                        e.reason == QLatin1String(reason::Timeout))) {
                e = CallError::make(reason::Timeout, QStringLiteral("'%1' excedeu %2 ms e foi cancelado")
                                                         .arg(it->second.method).arg(it->second.timeoutMs));
            }
            finish(id, false, {}, e);
        }
    } else {
        protocolFailure(QStringLiteral("mensagem '%1' não esperada do processo auxiliar").arg(kind));
    }
}

void HelperClient::finish(qint64 id, bool ok, const QJsonValue& value, const CallError& error) {
    auto it = pending_.find(id);
    if (it == pending_.end()) return;
    pending_.erase(it);
    if (ok) {
        consecutiveFailures_ = 0;
        emit callSucceeded(id, value);
    } else {
        emit callFailed(id, error);
    }
    if (pending_.empty() && state_ != State::Starting) tick_.stop();
}

void HelperClient::onTick() {
    std::vector<qint64> killFor;
    for (auto& [id, p] : pending_) {
        if (!p.sent) continue;
        if (!p.cancelSent && p.deadline.hasExpired()) {
            p.timedOut = true;
            p.cancelSent = true;
            p.graceDeadline = QDeadlineTimer(config_.cancelGraceMs);
            writeMessage(makeCancel(id));
        } else if (p.cancelSent && p.graceDeadline.hasExpired()) {
            killFor.push_back(id);
        }
    }
    if (!killFor.empty() && process_) {
        // The helper ignored the cancel: fail these calls as timeout and kill it. Other pending
        // calls then fail as helper_crashed in onFinished().
        for (qint64 id : killFor) {
            const QString method = pending_[id].method;
            finish(id, false, {}, CallError::make(reason::Timeout,
                                                  QStringLiteral("'%1' não respondeu ao cancelamento; processo "
                                                                 "auxiliar encerrado").arg(method)));
        }
        retire(reason::HelperCrashed,
               QStringLiteral("processo auxiliar encerrado por não responder ao cancelamento"));
    }
}

void HelperClient::failAll(const char* code, const QString& reason) {
    std::vector<qint64> ids;
    for (const auto& [id, p] : pending_) ids.push_back(id);
    for (qint64 id : ids) finish(id, false, {}, CallError::make(code, reason));
}

void HelperClient::onProcessError(QProcess::ProcessError error) {
    if (error == QProcess::FailedToStart) {
        helloTimer_.stop();
        exitReason_ = QStringLiteral("não foi possível iniciar o processo auxiliar (%1): %2")
                          .arg(config_.program, process_->errorString());
        ++consecutiveFailures_;
        QProcess* old = process_;
        process_ = nullptr;
        old->disconnect(this);
        old->deleteLater();
        setState(consecutiveFailures_ >= config_.maxRestarts ? State::Unavailable : State::Stopped);
        failAllLater(reason::HelperUnavailable, exitReason_);
        emit helperFinished(-1, exitReason_);
    }
}

void HelperClient::onFinished(int exitCode, QProcess::ExitStatus status) {
    helloTimer_.stop();
    const bool clean = stopping_ && status == QProcess::NormalExit && exitCode == 0;
    QString reason = exitReason_;
    if (reason.isEmpty()) {
        reason = status == QProcess::CrashExit ? QStringLiteral("o processo auxiliar travou ou foi encerrado")
                                               : QStringLiteral("o processo auxiliar foi encerrado (código de saída %1)")
                                                     .arg(exitCode);
    }
    const bool wasStarting = state_ == State::Starting;
    if (!clean) ++consecutiveFailures_;
    setState(consecutiveFailures_ >= config_.maxRestarts ? State::Unavailable : State::Stopped);
    failAll(wasStarting ? reason::HelperUnavailable : reason::HelperCrashed, reason);
    emit helperFinished(exitCode, reason);
}

}  // namespace gk::ipc
