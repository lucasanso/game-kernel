// Tests of real-time protection (M11). The batching rules run with a simulated clock and file probe; the
// watcher and the monitor run against real folders (ReadDirectoryChangesW on Windows, inotify on Linux) and
// real scans with isolated gk-scanworker processes. Samples are generated here (EICAR assembled at run
// time); nothing is executed. Driven by pytest (tests/integration/test_cpp_realtime.py).
#include "gk/realtime/batcher.hpp"
#include "gk/realtime/monitor.hpp"
#include "gk/realtime/watcher.hpp"

#include "gk/db.hpp"
#include "gk/quarantine.hpp"
#include "gk/risk.hpp"
#include "gk/text.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QtTest>

#include <algorithm>
#include <functional>
#include <map>

using namespace gk::realtime;

namespace {

QByteArray eicar() {
    // Assembled at run time so this source file is not itself a test signature.
    return QByteArray("X5O!P%@AP[4\\PZX54(P^)7CC)7}$") + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*";
}

bool writeFile(const QString& path, const QByteArray& data) {
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) return false;
    return f.write(data) == data.size();
}

QString clean(const QString& p) { return DirectoryWatcher::cleanFolder(p); }

// A file system made of a map, for the batching rules.
struct FakeFs {
    std::map<QString, FileState> files;
    Probe probe() {
        return [this](const QString& p) {
            const auto it = files.find(p);
            return it == files.end() ? FileState{} : it->second;
        };
    }
    void file(const QString& p, qint64 size, qint64 mtime = 1, bool readable = true) { files[p] = {true, false, size, mtime, readable}; }
    void dir(const QString& p) { files[p] = {true, true, 0, 0, true}; }
};

Change change(const QString& path, ChangeKind kind, bool directory = false) { return Change{path, kind, directory}; }

// Waits until `done` holds over the events collected so far (or the time runs out).
bool collect(const std::function<bool()>& done, int ms = 15000) {
    QElapsedTimer t;
    t.start();
    while (!done() && t.elapsed() < ms) QTest::qWait(50);
    return done();
}

bool has(const QList<Change>& seen, const QString& path, std::initializer_list<ChangeKind> kinds) {
    for (const Change& c : seen)
        if (clean(c.path) == clean(path) && std::find(kinds.begin(), kinds.end(), c.kind) != kinds.end()) return true;
    return false;
}

gk::Evidence evidence(gk::Source source, const char* verdict, gk::Risk severity = gk::Risk::High) {
    gk::Evidence e;
    e.rule_id = "t";
    e.title = "teste";
    e.source = source;
    e.severity = severity;
    if (verdict) e.details["verdict"] = verdict;
    return e;
}

}  // namespace

class TestRealtime : public QObject {
    Q_OBJECT

    gk::scan::Config configFor(const QTemporaryDir& data) {
        return gk::scan::Config::defaults(QCoreApplication::applicationDirPath(), data.path());
    }
    static Settings settingsFor(const QStringList& folders) {
        Settings s;
        s.enabled = true;
        s.folders = folders;
        s.batchSeconds = 2;
        s.stableSeconds = 1;
        return s;
    }
    static QList<QJsonObject> events(const QTemporaryDir& data) {
        QList<QJsonObject> out;
        const auto db = gk::db::Database::open_readonly(gk::text::utf8_path(QDir(data.path()).filePath("gamekernel.db").toStdString()));
        for (const auto& e : db->list_realtime_events(100))
            out << QJsonDocument::fromJson(QByteArray::fromStdString(e.dump())).object();
        return out;
    }

private slots:
    // ------------------------------------------------------------------------------------- batching
    void batcherReleasesFilesOnlyWhenTheyStoppedChanging() {
        FakeFs fs;
        BatcherOptions o;
        o.stableMs = 2000;
        o.batchMs = 8000;
        o.maxWaitMs = 30000;
        ChangeBatcher b(o);
        fs.file("/g/setup.exe", 100);
        b.add(change("/g/setup.exe", ChangeKind::Added), 0);
        QVERIFY(b.take(1000, fs.probe()).empty());    // events still arriving
        QVERIFY(b.take(2000, fs.probe()).empty());    // first look: size and time recorded
        QVERIFY(b.take(4000, fs.probe()).empty());    // stable now, but the gathering window is open
        Batch batch = b.take(8000, fs.probe());
        QCOMPARE(batch.files, QStringList{"/g/setup.exe"});
        QVERIFY(batch.stillWriting.isEmpty());
        QCOMPARE(b.pending(), 0);

        // A file that keeps growing waits; once it settles it goes out on its own.
        fs.file("/g/repack.bin", 10);
        b.add(change("/g/repack.bin", ChangeKind::Added), 10000);
        for (qint64 t = 12000; t <= 20000; t += 2000) {
            fs.file("/g/repack.bin", t, t);           // size and time change between probes
            QVERIFY(b.take(t, fs.probe()).empty());
        }
        batch = b.take(22000, fs.probe());
        QCOMPARE(batch.files, QStringList{"/g/repack.bin"});

        // A file locked by its writer (unreadable) waits too, up to the maximum, then is analysed anyway.
        fs.file("/g/locked.dll", 50, 1, false);
        b.add(change("/g/locked.dll", ChangeKind::Modified), 30000);
        for (qint64 t = 32000; t < 60000; t += 2000) QVERIFY(b.take(t, fs.probe()).empty());
        batch = b.take(60000, fs.probe());
        QCOMPARE(batch.files, QStringList{"/g/locked.dll"});
        QCOMPARE(batch.stillWriting, QStringList{"/g/locked.dll"});

        // A new event makes a stable file wait again.
        fs.file("/g/a.dll", 1);
        b.add(change("/g/a.dll", ChangeKind::Added), 70000);
        QVERIFY(b.take(72000, fs.probe()).empty());
        QVERIFY(b.take(74000, fs.probe()).empty());
        fs.file("/g/a.dll", 2, 77000);
        b.add(change("/g/a.dll", ChangeKind::Modified), 77000);
        QVERIFY(b.take(78000, fs.probe()).empty());   // the event is too recent
        QVERIFY(b.take(79000, fs.probe()).empty());   // size and time differ from the last look: wait again
        QCOMPARE(b.take(81000, fs.probe()).files, QStringList{"/g/a.dll"});
    }

    void batcherDropsWhatDisappearedAndWhatIsExcluded() {
        FakeFs fs;
        ChangeBatcher b(BatcherOptions{1000, 2000, 60000, 100});
        b.setExcluded({"/data"});
        fs.file("/g/x.exe", 1);
        b.add(change("/g/x.exe", ChangeKind::Added), 0);
        b.add(change("/g/x.exe", ChangeKind::Removed), 100);
        QCOMPARE(b.pending(), 0);
        // Browser downloads: written under a temporary name, then renamed.
        fs.file("/g/game.exe", 5);
        b.add(change("/g/game.exe.part", ChangeKind::Added), 0);
        b.add(change("/g/game.exe.part", ChangeKind::RenamedFrom), 500);
        b.add(change("/g/game.exe", ChangeKind::RenamedTo), 500);
        b.add(change("/data/gamekernel.db", ChangeKind::Modified), 500);   // the program's own files
        QVERIFY(b.excluded("/data/quarantine/x.gkq"));
        QVERIFY(!b.excluded("/database/x"));
        QCOMPARE(b.pending(), 1);
        // A folder whose content changed is not scanned as a whole; a folder that appeared is.
        fs.dir("/g/saves");
        fs.dir("/g/mods");
        fs.file("/g/mods/mod.dll", 3);
        b.add(change("/g/saves", ChangeKind::Modified), 500);
        b.add(change("/g/mods", ChangeKind::RenamedTo), 500);
        b.add(change("/g/mods/mod.dll", ChangeKind::Added), 500);
        QVERIFY(b.take(1600, fs.probe()).empty());
        const Batch batch = b.take(3000, fs.probe());
        QCOMPARE(batch.folders, QStringList{"/g/mods"});
        QCOMPARE(batch.files, QStringList{"/g/game.exe"});   // mod.dll is covered by its folder
        QCOMPARE(batch.targets(), (QStringList{"/g/mods", "/g/game.exe"}));
        QCOMPARE(b.pending(), 0);
        // Removing a folder drops what was pending inside it.
        b.add(change("/g/new/a.exe", ChangeKind::Added), 4000);
        b.add(change("/g/new/b.exe", ChangeKind::Added), 4000);
        b.add(change("/g/new", ChangeKind::Removed), 4100);
        QCOMPARE(b.pending(), 0);
        // Files that vanished before being looked at are dropped too.
        b.add(change("/g/gone.exe", ChangeKind::Added), 5000);
        QVERIFY(b.take(9000, fs.probe()).empty());
        QCOMPARE(b.pending(), 0);
    }

    void batcherFallsBackToRescanningTheFolder() {
        FakeFs fs;
        ChangeBatcher b(BatcherOptions{1000, 2000, 60000, 5});
        b.setRoots({"/g"});
        fs.dir("/g");
        for (int i = 0; i < 8; ++i) {
            fs.file(QStringLiteral("/g/f%1.dat").arg(i), 1);
            b.add(change(QStringLiteral("/g/f%1.dat").arg(i), ChangeKind::Added), 0);
        }
        QCOMPARE(b.collapses(), 1);
        QVERIFY(b.pending() <= 5);
        Batch batch = b.take(3000, fs.probe());
        QCOMPARE(batch.folders, QStringList{"/g"});
        QVERIFY(batch.files.isEmpty());
        // Events lost by the operating system: the folder is rescanned.
        b.rescan("/g", 4000);
        batch = b.take(6000, fs.probe());
        QCOMPARE(batch.folders, QStringList{"/g"});
    }

    void onlySignatureConfirmedThreatsQualifyForAutomaticQuarantine() {
        gk::FileResult r;
        r.classification = gk::Classification::Malware;
        r.evidences = {evidence(gk::Source::Yara, "test")};
        QVERIFY(gk::risk::confirmed_by_signature(r));
        r.evidences = {evidence(gk::Source::Signature, nullptr)};                 // ClamAV
        QVERIFY(gk::risk::confirmed_by_signature(r));
        r.evidences = {evidence(gk::Source::Reputation, "bad")};                  // local IOC
        QVERIFY(gk::risk::confirmed_by_signature(r));
        r.evidences = {evidence(gk::Source::Behavioral, nullptr, gk::Risk::Critical)};
        QVERIFY(!gk::risk::confirmed_by_signature(r));                            // sandbox behaviour: the user decides
        r.evidences = {evidence(gk::Source::Heuristic, nullptr, gk::Risk::Critical), evidence(gk::Source::Yara, "pua")};
        QVERIFY(!gk::risk::confirmed_by_signature(r));
        r.evidences = {evidence(gk::Source::Yara, "malware")};
        r.possible_false_positive = true;
        QVERIFY(!gk::risk::confirmed_by_signature(r));
        r.possible_false_positive = false;
        r.classification = gk::Classification::Suspicious;
        QVERIFY(!gk::risk::confirmed_by_signature(r));
    }

    // -------------------------------------------------------------------------------------- watcher
    void watcherReportsCreatedChangedRenamedAndRemovedFiles() {
        QVERIFY(DirectoryWatcher::supported());
        QTemporaryDir root;
        DirectoryWatcher w;
        QList<Change> seen;
        connect(&w, &DirectoryWatcher::changes, this, [&seen](const QList<Change>& batch) { seen += batch; });
        QVERIFY(w.start({root.path()}).isEmpty());
        QVERIFY(w.active());
        QCOMPARE(w.roots(), QStringList{clean(root.path())});

        const QString file = root.filePath("crack.dll");
        QVERIFY(writeFile(file, "MZ"));
        QVERIFY(collect([&] { return has(seen, file, {ChangeKind::Added}); }));
        {
            QFile f(file);
            QVERIFY(f.open(QIODevice::Append));
            f.write("more");
        }
        QVERIFY(collect([&] { return has(seen, file, {ChangeKind::Modified}); }));
        // Subfolders are watched too, including ones created after the start.
        QVERIFY(QDir(root.path()).mkpath("mods/sub"));
        QVERIFY(collect([&] { return has(seen, root.filePath("mods"), {ChangeKind::Added}); }));
        QTest::qWait(300);
        const QString deep = root.filePath("mods/sub/loader.exe");
        QVERIFY(writeFile(deep, "MZ"));
        QVERIFY(collect([&] { return has(seen, deep, {ChangeKind::Added, ChangeKind::Modified}); }));
        const QString renamed = root.filePath("mods/sub/loader2.exe");
        QVERIFY(QFile::rename(deep, renamed));
        QVERIFY(collect([&] {
            return has(seen, deep, {ChangeKind::RenamedFrom}) && has(seen, renamed, {ChangeKind::RenamedTo});
        }));
        QVERIFY(QFile::remove(renamed));
        QVERIFY(collect([&] { return has(seen, renamed, {ChangeKind::Removed}); }));
        w.stop();
        QVERIFY(!w.active());
        QVERIFY(w.roots().isEmpty());
        seen.clear();
        QVERIFY(writeFile(root.filePath("after.exe"), "MZ"));
        QTest::qWait(500);
        QVERIFY(seen.isEmpty());   // nothing after stop()
    }

    void watcherRefusesMissingFoldersAndCoversNestedOnes() {
        QTemporaryDir root;
        QVERIFY(QDir(root.path()).mkpath("Jogos/Sub"));
        DirectoryWatcher w;
        const auto refused = w.start({root.filePath("nao-existe"), root.filePath("Jogos"), root.filePath("Jogos/Sub"),
                                      root.filePath("Jogos")});
        QCOMPARE(refused.size(), 1);
        QCOMPARE(refused.first().folder, clean(root.filePath("nao-existe")));
        QCOMPARE(refused.first().reason, QStringLiteral("a pasta não existe"));
        QCOMPARE(w.roots(), QStringList{clean(root.filePath("Jogos"))});   // Sub is covered by Jogos
        QVERIFY(w.start({root.filePath("nao-existe")}).size() == 1);
        QVERIFY(!w.active());
    }

    void watcherSaysWhenAFolderCanNoLongerBeWatched() {
        QTemporaryDir root;
        const QString folder = root.filePath("Downloads");
        QVERIFY(QDir().mkpath(folder));
        DirectoryWatcher w;
        QSignalSpy failed(&w, &DirectoryWatcher::failed);
        QVERIFY(w.start({folder}).isEmpty());
        QVERIFY(QDir(folder).removeRecursively());
        QVERIFY(failed.count() > 0 || failed.wait(15000));
        QCOMPARE(clean(failed.first().at(0).toString()), clean(folder));
        QVERIFY(!failed.first().at(1).toString().isEmpty());
    }

    // -------------------------------------------------------------------------------------- monitor
    void monitorScansNewFilesAndReportsFindings() {
        QTemporaryDir data, game;
        Monitor m(configFor(data), QDir(data.path()).filePath("quarantine"));
        m.setTickInterval(100);
        QSignalSpy detected(&m, &Monitor::detected);
        QSignalSpy batches(&m, &Monitor::batchFinished);
        m.apply(settingsFor({game.path()}));
        QVERIFY(m.active());
        QJsonObject st = m.status();
        QVERIFY(st.value("enabled").toBool() && st.value("active").toBool());
        QCOMPARE(st.value("folders").toArray().first().toObject().value("watching").toBool(), true);

        QVERIFY(writeFile(game.filePath("config.ini"), "[video]\nfullscreen=1\n"));
        QVERIFY(writeFile(game.filePath("baixado/leia_eicar.com"), eicar()));
        QVERIFY(detected.count() > 0 || detected.wait(120000));
        const QJsonObject d = detected.first().at(0).toJsonObject();
        QVERIFY2(d.value("path").toString().endsWith("leia_eicar.com"), qPrintable(QJsonDocument(d).toJson()));
        QCOMPARE(d.value("classification").toString(), QStringLiteral("malware"));
        QVERIFY(d.value("risk").toInt() >= 4);
        QCOMPARE(d.value("action").toString(), QStringLiteral("notified"));   // automatic quarantine is off
        QVERIFY(!d.value("detection").toString().isEmpty());
        QVERIFY(d.value("scan_id").toInteger() > 0);
        QVERIFY(QFileInfo::exists(game.filePath("baixado/leia_eicar.com")));   // nothing moved without permission
        QVERIFY(batches.count() > 0);
        QCOMPARE(batches.last().at(0).toJsonObject().value("status").toString(), QStringLiteral("completed"));

        // Recorded: the event, and the batch as a scan of origin "realtime" that the history can hide.
        bool recorded = false;
        for (const QJsonObject& e : events(data))
            if (e.value("event").toString() == QLatin1String("detected") && e.value("path").toString().endsWith("leia_eicar.com"))
                recorded = e.value("detail").toObject().value("action").toString() == QLatin1String("notified");
        QVERIFY(recorded);
        const auto db = gk::db::Database::open_readonly(gk::text::utf8_path(QDir(data.path()).filePath("gamekernel.db").toStdString()));
        const auto all = db->list_scans(50);
        QVERIFY(!all.empty());
        QCOMPARE(QString::fromStdString(all.front().value("origin", "")), QStringLiteral("realtime"));
        QVERIFY(db->list_scans(50, "realtime").empty());
        // The clean file was scanned without a notification.
        for (const auto& args : detected) QVERIFY(!args.at(0).toJsonObject().value("path").toString().endsWith("config.ini"));
        QTRY_VERIFY_WITH_TIMEOUT(m.status().value("files_scanned").toInteger() >= 2 || batches.count() >= 2, 60000);
        st = m.status();
        QVERIFY(st.value("batches").toInteger() >= 1);
        QVERIFY(st.value("detections").toInteger() >= 1);

        // Turning it off stops watching.
        Settings off = settingsFor({game.path()});
        off.enabled = false;
        m.apply(off);
        QVERIFY(!m.active());
        const int before = batches.count();
        QVERIFY(writeFile(game.filePath("depois.com"), eicar()));
        QTest::qWait(4000);
        QCOMPARE(batches.count(), before);
    }

    void monitorQuarantinesConfirmedThreatsOnlyWhenAllowed() {
        QTemporaryDir data, game;
        const QString vaultDir = QDir(data.path()).filePath("quarantine");
        Monitor m(configFor(data), vaultDir);
        m.setTickInterval(100);
        QSignalSpy detected(&m, &Monitor::detected);
        QSignalSpy recorded(&m, &Monitor::eventRecorded);
        Settings s = settingsFor({game.path()});
        s.autoQuarantine = true;
        s.notifyMinRisk = 5;   // CRITICAL: the notification level must not stop a confirmed (HIGH) threat being isolated
        m.apply(s);
        const QString sample = game.filePath("trainer/leia_eicar.com");
        QVERIFY(writeFile(sample, eicar()));
        QVERIFY(detected.count() > 0 || detected.wait(120000));
        const QJsonObject d = detected.first().at(0).toJsonObject();
        QCOMPARE(d.value("action").toString(), QStringLiteral("quarantined"));
        QVERIFY(!d.value("quarantine_id").toString().isEmpty());
        QTRY_VERIFY_WITH_TIMEOUT(!QFileInfo::exists(sample), 10000);
        QCOMPARE(m.status().value("quarantined").toInteger(), 1);

        const auto vault = gk::quarantine::Vault::open(gk::text::utf8_path(vaultDir.toStdString()));
        auto db = gk::db::Database::open(gk::text::utf8_path(QDir(data.path()).filePath("gamekernel.db").toStdString()));
        const auto items = db->list_quarantine("quarantined");
        QCOMPARE(items.size(), std::size_t(1));
        QVERIFY(QString::fromStdString(items.front().reason).contains(QStringLiteral("tempo real")));
        QCOMPARE(QString::fromStdString(items.front().id), d.value("quarantine_id").toString());

        // The user restores it (a false positive, say): it comes back and is not isolated again.
        gk::quarantine::Manager manager(*vault, *db);
        manager.restore(items.front().id, std::nullopt, false);
        QVERIFY(QFileInfo::exists(sample));
        QTRY_VERIFY_WITH_TIMEOUT(
            [&] {
                for (const auto& args : recorded) {
                    const QJsonObject e = args.at(0).toJsonObject();
                    if (e.value("event").toString() == QLatin1String("detected") &&
                        e.value("detail").toObject().value("action").toString() == QLatin1String("restored_before"))
                        return true;
                }
                return false;
            }(),
            120000);
        QVERIFY(QFileInfo::exists(sample));
        QCOMPARE(detected.count(), 1);   // no second notification for what the user chose to keep
    }

    void monitorNeverWatchesTheProgramData() {
        QTemporaryDir root;
        const QString dataDir = root.filePath("GameKernelData");
        QVERIFY(QDir().mkpath(dataDir));
        gk::scan::Config config = gk::scan::Config::defaults(QCoreApplication::applicationDirPath(), dataDir);
        Monitor m(config, QDir(dataDir).filePath("quarantine"));
        m.setTickInterval(100);
        QSignalSpy batches(&m, &Monitor::batchFinished);
        // A folder inside the data folder is refused; a parent folder is watched without its data subfolder.
        m.apply(settingsFor({root.path(), QDir(dataDir).filePath("temp")}));
        QVERIFY(QDir().mkpath(QDir(dataDir).filePath("temp")));
        const QJsonArray folders = m.status().value("folders").toArray();
        QCOMPARE(folders.size(), 2);
        QVERIFY(folders.at(0).toObject().value("watching").toBool());
        QVERIFY(!folders.at(1).toObject().value("watching").toBool());
        QVERIFY(!folders.at(1).toObject().value("error").toString().isEmpty());
        QVERIFY(writeFile(QDir(dataDir).filePath("temp/copia.com"), eicar()));
        QTest::qWait(5000);
        QCOMPARE(batches.count(), 0);

        // A folder that does not exist is reported, not silently ignored.
        m.apply(settingsFor({root.filePath("Sumiu")}));
        QVERIFY(!m.active());
        const QJsonObject f = m.status().value("folders").toArray().first().toObject();
        QCOMPARE(f.value("watching").toBool(), false);
        QCOMPARE(f.value("error").toString(), QStringLiteral("a pasta não existe"));
    }
};

QTEST_GUILESS_MAIN(TestRealtime)
#include "tst_realtime.moc"
