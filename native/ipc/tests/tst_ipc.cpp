// Tests of the C++ gk-ipc client. The process tests start the *real* Python helpers
// (tests/ipc/fault_helper.py and gk_helper.py) — they are driven by pytest
// (tests/native/test_native_ipc.py), which sets GK_PYTHON and GK_REPO.
#include "gk/ipc/helper_client.hpp"
#include "gk/ipc/protocol.hpp"

#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QtEndian>
#include <QtTest>

using namespace gk::ipc;

namespace {

QByteArray rawFrame(const QByteArray& payload) {
    QByteArray f(4, Qt::Uninitialized);
    qToLittleEndian<quint32>(quint32(payload.size()), f.data());
    return f + payload;
}

QJsonObject response(qint64 id) {
    return QJsonObject{{"proto", 1}, {"type", "response"}, {"id", double(id)}, {"ok", true}, {"result", 1}};
}

}  // namespace

class TestIpc : public QObject {
    Q_OBJECT

    QString python_;
    QString repo_;
    QTemporaryDir dataDir_;

    HelperConfig faultConfig() const {
        HelperConfig c = HelperConfig::forDevelopment(python_, repo_, dataDir_.path());
        c.arguments = {QStringLiteral("-I"), QDir(repo_).filePath(QStringLiteral("tests/ipc/fault_helper.py"))};
        c.cancelGraceMs = 800;
        return c;
    }

private slots:
    void initTestCase() {
        python_ = qEnvironmentVariable("GK_PYTHON");
        repo_ = qEnvironmentVariable("GK_REPO");
        QVERIFY(dataDir_.isValid());
    }

    // ---------------------------------------------------------------- framing (no process)
    void decoderHandlesArbitraryFragmentation() {
        QByteArray stream = *encodeFrame(response(1)) + *encodeFrame(response(2)) + *encodeFrame(response(3));
        FrameDecoder d;
        for (char c : stream) d.feed(QByteArray(1, c));
        QVERIFY(!d.failed());
        QList<qint64> ids;
        while (d.hasMessage()) ids << qint64(d.takeMessage().value("id").toDouble());
        QCOMPARE(ids, (QList<qint64>{1, 2, 3}));
        QCOMPARE(d.bufferedBytes(), 0);
    }

    void decoderRejectsMalformedFrames_data() {
        QTest::addColumn<QByteArray>("bytes");
        QTest::newRow("zero length") << rawFrame(QByteArray());
        QByteArray huge(4, Qt::Uninitialized);
        qToLittleEndian<quint32>(quint32(kDefaultMaxFrame + 1), huge.data());
        QTest::newRow("oversized") << huge;
        QTest::newRow("invalid utf8") << rawFrame(QByteArray("\xff\xfe{}", 4));
        QTest::newRow("invalid json") << rawFrame("{nope");
        QTest::newRow("not an object") << rawFrame("[1,2]");
        QTest::newRow("NaN") << rawFrame(R"({"proto":1,"type":"log","level":"INFO","message":NaN})");
        QTest::newRow("wrong version") << rawFrame(R"({"proto":2,"type":"log","level":"INFO","message":"x"})");
        QTest::newRow("unknown type") << rawFrame(R"({"proto":1,"type":"bogus"})");
        QTest::newRow("fractional id") << rawFrame(R"({"proto":1,"type":"response","id":1.5,"ok":true,"result":1})");
        QTest::newRow("id too large") << rawFrame(R"({"proto":1,"type":"cancel","id":9007199254740992})");
        QTest::newRow("error without code") << rawFrame(R"({"proto":1,"type":"response","id":1,"ok":false,"error":{}})");
    }
    void decoderRejectsMalformedFrames() {
        QFETCH(QByteArray, bytes);
        FrameDecoder d;
        d.feed(bytes);
        QVERIFY(d.failed());
        QVERIFY(!d.hasMessage());
        d.feed(*encodeFrame(response(1)));   // stays failed: the stream cannot be resynchronised
        QVERIFY(!d.hasMessage());
    }

    void decoderAcceptsUnknownFields() {
        QJsonObject m = response(9);
        m.insert("future", QJsonObject{{"x", 1}});
        FrameDecoder d;
        d.feed(*encodeFrame(m));
        QVERIFY(d.hasMessage());
    }

    void encodeRespectsLimit() {
        QJsonObject big{{"proto", 1}, {"type", "log"}, {"level", "INFO"}, {"message", QString(200, 'x')}};
        QVERIFY(!encodeFrame(big, 100).has_value());
        QVERIFY(encodeFrame(big).has_value());
    }

    void requestBuilderIsValid() {
        QVERIFY(!validateMessage(makeRequest(5, "reports.generate", {{"scan_id", 1}}, 1000)).has_value());
        QVERIFY(validateMessage(makeRequest(5, "noDots", {}, 0)).has_value());
        QVERIFY(!validateMessage(makeCancel(5)).has_value());
    }

    void retryableCodes() {
        QVERIFY(isRetryable("timeout"));
        QVERIFY(isRetryable("helper_crashed"));
        QVERIFY(!isRetryable("invalid_params"));
    }

    // ---------------------------------------------------------------- real helper processes
    void pingAndHello() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido (execute via pytest)");
        HelperClient c(faultConfig());
        auto r = c.callBlocking("system.ping", {{"echo", QStringLiteral("olá")}});
        QVERIFY2(r.ok, qPrintable(r.error.message));
        QCOMPARE(r.value.toObject().value("echo").toString(), QStringLiteral("olá"));
        QCOMPARE(c.hello().value("helper").toString(), QStringLiteral("gk-helper"));
        QVERIFY(c.hello().value("netguard").toBool());
        QCOMPARE(c.state(), HelperClient::State::Ready);
    }

    void serviceErrorsKeepHelperAlive() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperClient c(faultConfig());
        auto r = c.callBlocking("test.raise");
        QVERIFY(!r.ok);
        QCOMPARE(r.error.code, QStringLiteral("internal_error"));
        QVERIFY(r.error.message.contains("falha proposital"));
        r = c.callBlocking("test.service_error");
        QCOMPARE(r.error.code, QStringLiteral("invalid_params"));
        QCOMPARE(r.error.details.value("field").toString(), QStringLiteral("x"));
        r = c.callBlocking("nope.method");
        QCOMPARE(r.error.code, QStringLiteral("unknown_method"));
        const qint64 pid = c.processId();
        QVERIFY(c.callBlocking("system.ping").ok);
        QCOMPARE(c.processId(), pid);   // same process: no restart was needed
    }

    void strayStdoutDoesNotCorruptProtocol() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperClient c(faultConfig());
        QVERIFY(c.callBlocking("test.stdout").ok);
        QVERIFY(c.callBlocking("system.ping").ok);
    }

    void eventsArriveInOrder() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperClient c(faultConfig());
        QList<int> seen;
        connect(&c, &HelperClient::eventReceived, this,
                [&](qint64, const QString& name, const QJsonObject& data) {
                    if (name == "progress") seen << data.value("i").toInt();
                });
        auto r = c.callBlocking("test.events", {{"count", 4}});
        QVERIFY(r.ok);
        QCOMPARE(seen, (QList<int>{0, 1, 2, 3}));
    }

    void concurrentCallsAreAllAnswered() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperClient c(faultConfig());
        QSignalSpy ok(&c, &HelperClient::callSucceeded);
        for (int i = 0; i < 20; ++i) c.call("system.ping", {{"echo", i}});
        QTRY_COMPARE_WITH_TIMEOUT(ok.count(), 20, 20000);
    }

    void cooperativeTimeout() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperClient c(faultConfig());
        QVERIFY(c.callBlocking("system.ping").ok);
        const qint64 pid = c.processId();
        auto r = c.callBlocking("test.sleep", {{"seconds", 30}}, 400);
        QVERIFY(!r.ok);
        QCOMPARE(r.error.code, QStringLiteral("timeout"));
        QVERIFY(c.callBlocking("system.ping").ok);
        QCOMPARE(c.processId(), pid);
    }

    void hungServiceIsKilledAndHelperRestarted() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperClient c(faultConfig());
        QVERIFY(c.callBlocking("system.ping").ok);
        const qint64 pid = c.processId();
        QElapsedTimer t;
        t.start();
        auto r = c.callBlocking("test.hang", {}, 300);
        QCOMPARE(r.error.code, QStringLiteral("timeout"));
        QVERIFY(t.elapsed() < 10000);
        auto again = c.callBlocking("system.ping");
        QVERIFY2(again.ok, qPrintable(again.error.message));
        QVERIFY(c.processId() != pid);
    }

    void hardCrashIsIsolated() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperClient c(faultConfig());
        QSignalSpy finished(&c, &HelperClient::helperFinished);
        auto r = c.callBlocking("test.crash");
        QCOMPARE(r.error.code, QStringLiteral("helper_crashed"));
        QVERIFY(r.error.retryable);
        QVERIFY(r.error.message.contains("3"));
        QTRY_VERIFY(finished.count() >= 1);
        QVERIFY(c.callBlocking("system.ping").ok);   // restarted transparently
        QCOMPARE(c.consecutiveFailures(), 0);
    }

    void repeatedCrashesMakeHelperUnavailable() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperConfig cfg = faultConfig();
        cfg.maxRestarts = 2;
        HelperClient c(cfg);
        QCOMPARE(c.callBlocking("test.crash").error.code, QStringLiteral("helper_crashed"));
        QCOMPARE(c.callBlocking("test.crash").error.code, QStringLiteral("helper_crashed"));
        QCOMPARE(c.state(), HelperClient::State::Unavailable);
        QCOMPARE(c.callBlocking("system.ping").error.code, QStringLiteral("helper_unavailable"));
        c.resetFailures();
        QVERIFY(c.callBlocking("system.ping").ok);
    }

    void memoryLimitIsEnforced() {
#if defined(Q_OS_LINUX)
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperConfig cfg = faultConfig();
        cfg.memoryLimitBytes = qint64(512) * 1024 * 1024;
        HelperClient c(cfg);
        QVERIFY(c.callBlocking("test.alloc", {{"mb", 16}}).ok);
        auto r = c.callBlocking("test.alloc", {{"mb", 1024}});
        QVERIFY(!r.ok);   // MemoryError inside the helper (or helper killed) — never the host
        QVERIFY(r.error.code == "internal_error" || r.error.code == "helper_crashed");
        QVERIFY(c.callBlocking("system.ping").ok);
#else
        QSKIP("limite por RLIMIT_AS testado apenas no Linux; no Windows é um Job Object");
#endif
    }

    void networkBlockedInHelper() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperClient c(faultConfig());
        auto r = c.callBlocking("test.network");
        QVERIFY(r.ok);
        QVERIFY(r.value.toObject().value("blocked").toBool());
    }

    void missingProgramIsUnavailable() {
        HelperConfig cfg = HelperConfig::forInstallation(dataDir_.path() + "/no-such-app", dataDir_.path());
        cfg.maxRestarts = 1;
        HelperClient c(cfg);
        auto r = c.callBlocking("system.ping", {}, 2000);
        QCOMPARE(r.error.code, QStringLiteral("helper_unavailable"));
        QCOMPARE(c.state(), HelperClient::State::Unavailable);
    }

    void relativeProgramIsRefused() {
        HelperConfig cfg;
        cfg.program = "gk-helper";
        HelperClient c(cfg);
        QCOMPARE(c.callBlocking("system.ping").error.code, QStringLiteral("helper_unavailable"));
    }

    void sanitizedEnvironmentDropsPythonVariables() {
        qputenv("PYTHONPATH", "/malicious");
        qputenv("GK_SECRET", "x");
        const QProcessEnvironment env = sanitizedEnvironment(dataDir_.path());
        QVERIFY(!env.contains("PYTHONPATH"));
        QVERIFY(!env.contains("GK_SECRET"));
        QCOMPARE(env.value("GAMEKERNEL_DATA_DIR"), QDir::toNativeSeparators(dataDir_.path()));
    }

    void stopClosesHelperCleanly() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperClient c(faultConfig());
        QVERIFY(c.callBlocking("system.ping").ok);
        QSignalSpy finished(&c, &HelperClient::helperFinished);
        c.stop();
        QTRY_COMPARE(finished.count(), 1);
        QCOMPARE(finished.at(0).at(0).toInt(), 0);
        QCOMPARE(c.consecutiveFailures(), 0);
    }

    void realHelperEntryPoint() {
        if (python_.isEmpty()) QSKIP("GK_PYTHON não definido");
        HelperClient c(HelperConfig::forDevelopment(python_, repo_, dataDir_.path()));
        auto r = c.callBlocking("system.info");
        QVERIFY2(r.ok, qPrintable(r.error.message + " | " + c.stderrTail().join("\n")));
        const QJsonObject info = r.value.toObject();
        QCOMPARE(info.value("protocol").toInt(), kProtocolVersion);
        QVERIFY(info.value("netguard").toBool());
        QVERIFY(info.value("methods").toObject().contains("system.ping"));
    }
};

QTEST_GUILESS_MAIN(TestIpc)
#include "tst_ipc.moc"
