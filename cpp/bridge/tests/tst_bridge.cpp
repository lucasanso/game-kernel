// Tests of the Qt service layer against the real core: scans with isolated gk-scanworker processes, the
// SQLite history, the encrypted quarantine vault and the integrity check. Driven by pytest
// (tests/integration/test_cpp_bridge.py). Every sample is generated here; nothing is executed.
#include "gk/bridge/services.hpp"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QtTest>

using namespace gk::bridge;

namespace {

QByteArray eicar() {
    // Assembled at run time so this source file is not itself a test signature.
    return QByteArray("X5O!P%@AP[4\\PZX54(P^)7CC)7}$") + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*";
}

void writeFile(const QString& path, const QByteArray& data) {
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    QVERIFY(f.open(QIODevice::WriteOnly));
    f.write(data);
}

QByteArray readFile(const QString& path) {
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

bool wait(QSignalSpy& spy, int ms = 120000) { return spy.count() > 0 || spy.wait(ms); }

}  // namespace

class TestBridge : public QObject {
    Q_OBJECT

    Environment envFor(const QTemporaryDir& data) {
        return Environment{QCoreApplication::applicationDirPath(), data.path()};
    }

private slots:
    void scanFindsTheThreatAndRecordsHistory() {
        QTemporaryDir data, game;
        writeFile(game.filePath(QStringLiteral("leia_eicar.com")), eicar());
        writeFile(game.filePath(QStringLiteral("config.ini")), "[video]\nfullscreen=1\n");
        ScanService scans(envFor(data));
        QSignalSpy started(&scans, &ScanService::started);
        QSignalSpy progress(&scans, &ScanService::progressChanged);
        QSignalSpy files(&scans, &ScanService::fileAnalyzed);
        QSignalSpy finished(&scans, &ScanService::finished);
        QVERIFY(scans.start({game.path()}, true, QStringLiteral("teste")));
        QVERIFY(!scans.start({game.path()}, true));                       // one scan at a time
        QVERIFY(scans.running());
        QVERIFY(wait(finished));
        QVERIFY(!scans.running());
        const QJsonObject summary = finished.takeFirst().at(0).toJsonObject();
        QVERIFY2(summary.value("status").toString() == QLatin1String("completed"),
                 qPrintable(QString::fromUtf8(QJsonDocument(summary).toJson(QJsonDocument::Compact))));
        QVERIFY(started.count() == 1 && started.first().at(0).toLongLong() > 0);
        const qint64 scanId = started.first().at(0).toLongLong();
        QCOMPARE(summary.value("scan_id").toInteger(), scanId);
        QVERIFY(progress.count() >= 1);
        bool eicarSeen = false;
        for (const auto& args : files) {
            const QJsonObject r = args.at(0).toJsonObject();
            if (r.value("name").toString() == QLatin1String("leia_eicar.com")) {
                eicarSeen = true;
                QCOMPARE(r.value("classification").toString(), QStringLiteral("malware"));
            }
        }
        QVERIFY(eicarSeen);

        HistoryService history(envFor(data));
        QSignalSpy listed(&history, &HistoryService::scansListed);
        const qint64 req = history.listScans();
        QVERIFY(wait(listed, 30000));
        QCOMPARE(listed.first().at(0).toLongLong(), req);
        const QJsonArray rows = listed.first().at(1).toJsonArray();
        QCOMPARE(rows.size(), 1);
        QCOMPARE(rows.first().toObject().value("scan_id").toInteger(), scanId);
        QCOMPARE(rows.first().toObject().value("max_risk_level").toString(), QStringLiteral("HIGH"));

        QSignalSpy loaded(&history, &HistoryService::scanLoaded);
        history.loadScan(scanId, true);
        QVERIFY(wait(loaded, 30000));
        const QJsonObject scan = loaded.first().at(1).toJsonObject();
        const QJsonArray findings = loaded.first().at(2).toJsonArray();
        QCOMPARE(scan.value("status").toString(), QStringLiteral("completed"));
        QVERIFY(scan.value("summary").toObject().contains(QStringLiteral("limitations")));
        QVERIFY(!findings.isEmpty());
        const QJsonObject top = findings.first().toObject();
        QCOMPARE(top.value("name").toString(), QStringLiteral("leia_eicar.com"));
        QVERIFY(!top.value("evidences").toArray().isEmpty());
        QSignalSpy failed(&history, &HistoryService::failed);
        history.loadScan(987654);
        QVERIFY(wait(failed, 30000));
        QVERIFY(failed.first().at(1).toString().contains(QStringLiteral("não encontrada")));
    }

    void pauseAndCancel() {
        QTemporaryDir data, game;
        for (int i = 0; i < 600; ++i)
            writeFile(game.filePath(QStringLiteral("dados/arquivo_%1.txt").arg(i)), QByteArray(2048, char('a' + i % 26)));
        ScanService scans(envFor(data));
        QSignalSpy progress(&scans, &ScanService::progressChanged);
        QSignalSpy finished(&scans, &ScanService::finished);
        QVERIFY(scans.start({game.path()}, true));
        QTRY_VERIFY_WITH_TIMEOUT(progress.count() > 0 || finished.count() > 0, 60000);
        QVERIFY2(finished.isEmpty(), qPrintable(QString::fromUtf8(
                     QJsonDocument(finished.isEmpty() ? QJsonObject{} : finished.first().at(0).toJsonObject()).toJson())));
        scans.pause();
        QTRY_VERIFY_WITH_TIMEOUT(std::any_of(progress.begin(), progress.end(),
                                             [](const QList<QVariant>& a) { return a.at(0).toJsonObject().value("paused").toBool(); }),
                                 60000);
        scans.cancel();
        QVERIFY(wait(finished));
        const QString status = finished.first().at(0).toJsonObject().value("status").toString();
        QVERIFY2(status == QLatin1String("cancelled") || status == QLatin1String("completed"), qPrintable(status));
        QVERIFY(!scans.running());
    }

    void quarantineRoundTrip() {
        QTemporaryDir data, files;
        const QString victim = files.filePath(QStringLiteral("jogo/suspeito.dll"));
        const QByteArray content = QByteArray("MZ") + QByteArray(4096, 'x');
        writeFile(victim, content);
        const QString sha = QString::fromLatin1(QCryptographicHash::hash(content, QCryptographicHash::Sha256).toHex());
        QuarantineService q(envFor(data));
        QSignalSpy done(&q, &QuarantineService::finished);
        QSignalSpy listed(&q, &QuarantineService::listed);

        QuarantineService::Item wrong{victim, QString(64, '0'), QStringLiteral("teste"), {}, {}, 4, 0};
        q.quarantine(wrong);                                              // changed since analysis: refused
        QVERIFY(wait(done, 60000));
        QCOMPARE(done.first().at(2).toBool(), false);
        QVERIFY(QFileInfo::exists(victim));
        done.clear();

        q.quarantine({victim, sha, QStringLiteral("detectado no teste"), QStringLiteral("suspicious"), QStringLiteral("regra X"), 4, 0});
        QVERIFY(wait(done, 60000));
        QVERIFY2(done.first().at(2).toBool(), qPrintable(done.first().at(4).toString()));
        const QString id = done.first().at(3).toJsonObject().value("id").toString();
        QCOMPARE(id.size(), 32);
        QVERIFY(!QFileInfo::exists(victim));                             // moved into the encrypted vault
        done.clear();

        q.list();
        QVERIFY(wait(listed, 60000));
        const QJsonArray items = listed.first().at(1).toJsonArray();
        QCOMPARE(items.size(), 1);
        QCOMPARE(items.first().toObject().value("sha256").toString(), sha);
        QCOMPARE(items.first().toObject().value("status").toString(), QStringLiteral("quarantined"));

        const QString restored = files.filePath(QStringLiteral("restaurado/suspeito.dll"));
        q.restore(id, restored);
        QVERIFY(wait(done, 60000));
        QVERIFY2(done.first().at(2).toBool(), qPrintable(done.first().at(4).toString()));
        QCOMPARE(readFile(restored), content);
        done.clear();

        q.verify();
        QVERIFY(wait(done, 60000));
        QVERIFY(done.first().at(2).toBool());
        QCOMPARE(done.first().at(3).toJsonObject().value("damaged").toArray().size(), 0);
        done.clear();

        q.erase(id);                                                      // already restored: no longer in quarantine
        QVERIFY(wait(done, 60000));
        QCOMPARE(done.first().at(2).toBool(), false);
        done.clear();

        const QString second = files.filePath(QStringLiteral("jogo/outro.exe"));
        writeFile(second, QByteArray("MZ") + QByteArray(1024, 'y'));
        q.quarantine({second, {}, QStringLiteral("teste"), {}, {}, 3, 0});
        QVERIFY(wait(done, 60000));
        const QString secondId = done.first().at(3).toJsonObject().value("id").toString();
        done.clear();
        q.erase(secondId);                                                // permanent deletion of the vault copy
        QVERIFY(wait(done, 60000));
        QVERIFY2(done.first().at(2).toBool(), qPrintable(done.first().at(4).toString()));
        listed.clear();
        q.list(true);
        QVERIFY(wait(listed, 60000));
        QHash<QString, QString> statusById;
        for (const auto& v : listed.first().at(1).toJsonArray())
            statusById.insert(v.toObject().value("id").toString(), v.toObject().value("status").toString());
        QCOMPARE(statusById.value(id), QStringLiteral("restored"));
        QCOMPARE(statusById.value(secondId), QStringLiteral("deleted"));
        QVERIFY(!QFileInfo::exists(second));
        QCOMPARE(readFile(restored), content);
    }

    void freshInstallationAndIntegrity() {
        QTemporaryDir data;
        HistoryService history(envFor(data));
        QSignalSpy listed(&history, &HistoryService::scansListed);
        history.listScans();
        QVERIFY(wait(listed, 30000));
        QVERIFY(listed.first().at(1).toJsonArray().isEmpty());
        QuarantineService q(envFor(data));
        QSignalSpy qListed(&q, &QuarantineService::listed);
        q.list();
        QVERIFY(wait(qListed, 30000));
        QVERIFY(qListed.first().at(1).toJsonArray().isEmpty());
        QVERIFY(!QFileInfo::exists(QDir(data.path()).filePath(QStringLiteral("gamekernel.db"))));   // reads never create it

        IntegrityService integrity(envFor(data));
        QSignalSpy checked(&integrity, &IntegrityService::checked);
        integrity.check();
        QVERIFY(wait(checked, 60000));
        const QJsonObject report = checked.first().at(0).toJsonObject();
        QCOMPARE(report.value("manifest_present").toBool(), false);   // development build: nothing to verify against
        QCOMPARE(report.value("ok").toBool(), false);
        QVERIFY(!report.value("detail").toString().isEmpty());
    }
    void realtimeProtectionThroughTheService() {
        QTemporaryDir data, game;
        RealtimeService rt(envFor(data));
        QVERIFY(RealtimeService::supported());
        QSignalSpy status(&rt, &RealtimeService::statusChanged);
        QSignalSpy detected(&rt, &RealtimeService::detected);
        QSignalSpy batches(&rt, &RealtimeService::batchFinished);
        gk::realtime::Settings s;
        s.enabled = true;
        s.folders = {game.path()};
        s.batchSeconds = 2;
        s.stableSeconds = 1;
        rt.apply(s);
        QTRY_VERIFY_WITH_TIMEOUT(rt.active(), 10000);
        QVERIFY(rt.status().value("folders").toArray().first().toObject().value("watching").toBool());
        writeFile(game.filePath(QStringLiteral("downloads/leia_eicar.com")), eicar());
        QVERIFY(wait(detected));
        const QJsonObject d = detected.first().at(0).toJsonObject();
        QCOMPARE(d.value("classification").toString(), QStringLiteral("malware"));
        QCOMPARE(d.value("action").toString(), QStringLiteral("notified"));
        QVERIFY(wait(batches));

        QSignalSpy listed(&rt, &RealtimeService::eventsListed);
        const qint64 req = rt.listEvents();
        QVERIFY(wait(listed));
        QCOMPARE(listed.first().at(0).toLongLong(), req);
        const QJsonArray events = listed.first().at(1).toJsonArray();
        QVERIFY(!events.isEmpty());
        const QJsonObject e = events.first().toObject();
        QCOMPARE(e.value("event").toString(), QStringLiteral("detected"));
        QVERIFY(e.value("risk_level").toString() == QLatin1String("HIGH") || e.value("risk_level").toString() == QLatin1String("CRITICAL"));
        QCOMPARE(e.value("detail").toObject().value("action").toString(), QStringLiteral("notified"));

        // The history leaves the real-time batches out unless asked for them.
        HistoryService history(envFor(data));
        QSignalSpy scans(&history, &HistoryService::scansListed);
        const qint64 hidden = history.listScans(50);
        const qint64 shown = history.listScans(50, true);
        QTRY_COMPARE_WITH_TIMEOUT(scans.count(), 2, 10000);
        for (const auto& args : scans) {
            const QJsonArray rows = args.at(1).toJsonArray();
            if (args.at(0).toLongLong() == hidden) QVERIFY(rows.isEmpty());
            if (args.at(0).toLongLong() == shown) {
                QVERIFY(!rows.isEmpty());
                QCOMPARE(rows.first().toObject().value("origin").toString(), QStringLiteral("realtime"));
            }
        }

        s.enabled = false;
        rt.apply(s);
        QTRY_VERIFY_WITH_TIMEOUT(!rt.active(), 10000);
    }
    void performanceAndOptimizerServices() {
        PerformanceService perf;
        QSignalSpy samples(&perf, &PerformanceService::sampled);
        perf.start(300);
        QTRY_VERIFY_WITH_TIMEOUT(samples.count() >= 2, 10000);
        QVERIFY(samples.first().at(0).toJsonObject().value("cpu_percent").isNull());   // first sample: no rates yet
        const QJsonObject s = samples.at(1).at(0).toJsonObject();
        QVERIFY(s.value("cpu_percent").isDouble());
        QVERIFY(s.value("memory_total").toInteger() > 0);
        QCOMPARE(s.value("self").toObject().value("pid").toInteger(), QCoreApplication::applicationPid());
        perf.stop();
        QTest::qWait(400);
        const int afterStop = samples.count();
        QTest::qWait(900);
        QCOMPARE(samples.count(), afterStop);

        QTemporaryDir data;
        OptimizerService opt(envFor(data));
        QVERIFY(opt.tempRoots().contains(QDir(data.path()).filePath(QStringLiteral("temp"))));
        QSignalSpy diagnosed(&opt, &OptimizerService::diagnosed);
        opt.diagnose({data.path()});
        QVERIFY(wait(diagnosed));
        QVERIFY(diagnosed.first().at(1).toJsonArray().size() >= 5);

        QSignalSpy failed(&opt, &OptimizerService::failed);
        opt.cleanTemp();   // nothing analysed: refused
        QVERIFY(wait(failed));
        const QString old = QDir(data.path()).filePath(QStringLiteral("temp/sessao-antiga.tmp"));
        writeFile(old, QByteArray(4096, 'x'));
        {
            QFile f(old);
            QVERIFY(f.open(QIODevice::ReadWrite));
            QVERIFY(f.setFileTime(QDateTime::currentDateTime().addDays(-3), QFileDevice::FileModificationTime));
        }
        writeFile(QDir(data.path()).filePath(QStringLiteral("temp/em-uso.tmp")), "recente");
        QSignalSpy analyzed(&opt, &OptimizerService::tempAnalyzed);
        opt.analyzeTemp(24);
        QVERIFY(wait(analyzed));
        QVERIFY(opt.hasPlan());
        const QJsonObject plan = analyzed.first().at(1).toJsonObject();
        QVERIFY(plan.value("files").toInteger() >= 1);
        QVERIFY(plan.value("bytes").toInteger() >= 4096);
        QVERIFY(plan.value("recent").toInteger() >= 1);
        QSignalSpy cleaned(&opt, &OptimizerService::tempCleaned);
        opt.cleanTemp();
        QVERIFY(!opt.hasPlan());   // a plan is used once
        QVERIFY(wait(cleaned));
        const QJsonObject r = cleaned.first().at(1).toJsonObject();
        QVERIFY(r.value("deleted").toInt() >= 1);
        QVERIFY(!r.contains("audit_error"));
        QVERIFY(!QFileInfo::exists(old));
        QVERIFY(QFileInfo::exists(QDir(data.path()).filePath(QStringLiteral("temp/em-uso.tmp"))));
    }

};

QTEST_MAIN(TestBridge)
#include "tst_bridge.moc"
