// Tests of the System Optimizer (M12): the read-only diagnostics on the real machine, and the two-step clean-up
// of temporary files on folders created here (old, recent, modified after the analysis, links never followed,
// folders swapped for links in between, files in use). Driven by pytest (tests/integration/test_cpp_perf.py).
#include "gk/sysopt/optimizer.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QtTest>

#include <atomic>
#include <chrono>
#include <filesystem>

#ifndef _WIN32
#include <unistd.h>
#endif

using namespace gk::sysopt;
namespace fs = std::filesystem;

namespace {

bool writeFile(const QString& path, const QByteArray& data) {
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    return f.open(QIODevice::WriteOnly) && f.write(data) == data.size();
}

fs::path native(const QString& p) {
#ifdef _WIN32
    return fs::path(QDir::toNativeSeparators(p).toStdWString());
#else
    return fs::path(QFile::encodeName(p).toStdString());
#endif
}

void age(const QString& path, int hours) {
    fs::last_write_time(native(path), fs::file_time_type::clock::now() - std::chrono::hours(hours));
}

}  // namespace

class TestSysopt : public QObject {
    Q_OBJECT

private slots:
    void diagnosticsOnlyReadAndAlwaysExplain() {
        QTemporaryDir games;
        const QList<Check> checks = diagnose({games.path()});
        QStringList ids;
        for (const Check& c : checks) {
            ids << c.id;
            QVERIFY2(!c.title.isEmpty() && !c.value.isEmpty(), qPrintable(c.id));
            QVERIFY2(QStringList({"ok", "attention", "info", "unavailable"}).contains(c.status), qPrintable(c.id + ": " + c.status));
            if (c.status == QLatin1String("attention")) QVERIFY2(!c.recommendation.isEmpty(), qPrintable(c.id));
            const QJsonObject j = toJson(c);
            QCOMPARE(j.value("id").toString(), c.id);
        }
        for (const char* id : {"power_plan", "game_mode", "background_recording", "gpu_scheduling", "memory", "startup_programs",
                               "pending_reboot"})
            QVERIFY2(ids.contains(QLatin1String(id)), id);
        QVERIFY(std::any_of(ids.begin(), ids.end(), [](const QString& id) { return id.startsWith(QStringLiteral("disk:")); }));
        for (const Check& c : checks) {
            if (c.id == QLatin1String("memory")) QVERIFY(c.status != QLatin1String("unavailable"));
#ifdef _WIN32
            if (c.id == QLatin1String("power_plan") || c.id == QLatin1String("game_mode")) QVERIFY2(c.status != QLatin1String("unavailable"), qPrintable(c.value));
#else
            if (c.id == QLatin1String("power_plan")) QCOMPARE(c.status, QStringLiteral("unavailable"));
#endif
        }
    }

    void temporaryFilesAreCleanedOnlyAsAnalysed() {
        QTemporaryDir box;
        const QString root = QDir(box.path()).filePath(QStringLiteral("Temp"));
        const QString outside = QDir(box.path()).filePath(QStringLiteral("MeusArquivos"));
        QVERIFY(writeFile(root + "/old1.tmp", QByteArray(1000, 'a')));
        QVERIFY(writeFile(root + "/instalador/old2.cab", QByteArray(2000, 'b')));
        QVERIFY(writeFile(root + "/instalador/sub/old3.log", QByteArray(300, 'c')));
        QVERIFY(writeFile(root + "/recente.tmp", "agora"));                   // in use by an installer, say
        QVERIFY(writeFile(root + "/muda.tmp", QByteArray(10, 'd')));
        QVERIFY(writeFile(root + "/troca/old4.tmp", QByteArray(10, 'e')));   // its folder becomes a link later
        QVERIFY(writeFile(outside + "/save.dat", "progresso do jogo"));
        for (const char* f : {"old1.tmp", "instalador/old2.cab", "instalador/sub/old3.log", "muda.tmp", "troca/old4.tmp"})
            age(root + "/" + f, 72);
        age(root + "/instalador/sub", 72);
        age(root + "/instalador", 72);
        age(outside + "/save.dat", 72);
#ifndef _WIN32
        QVERIFY(QFile::link(outside, root + "/atalho-para-fora"));          // never followed
        QVERIFY(QFile::link(outside + "/save.dat", root + "/save-link"));  // never deleted
#endif
        // Unsafe roots are refused.
        QVERIFY(analyzeTemp({QDir::rootPath(), QDir::homePath()}).roots.isEmpty());
        std::atomic<bool> cancel{true};
        QVERIFY(analyzeTemp({root}, 24, &cancel).files.isEmpty());

        const TempPlan plan = analyzeTemp({root, root}, 24);
        QCOMPARE(plan.roots.size(), 1);
        QCOMPARE(plan.files.size(), 5);
        QCOMPARE(plan.bytes, qint64(1000 + 2000 + 300 + 10 + 10));
        QCOMPARE(plan.recent, 1);
#ifndef _WIN32
        QCOMPARE(plan.links, 2);
#endif
        QVERIFY(plan.dirs.contains(QFileInfo(root + "/instalador/sub").canonicalFilePath()));
        QVERIFY(plan.dirs.indexOf(QFileInfo(root + "/instalador/sub").canonicalFilePath()) <
                plan.dirs.indexOf(QFileInfo(root + "/instalador").canonicalFilePath()));   // deepest first
        const QJsonObject pj = toJson(plan);
        QCOMPARE(pj.value("files").toInteger(), 5);

        // Between the analysis and the clean-up: one file changes, one folder is swapped for a link to user data.
        {
            QFile f(root + "/muda.tmp");
            QVERIFY(f.open(QIODevice::Append));
            f.write("mais");
        }
#ifndef _WIN32
        QVERIFY(QDir(root + "/troca").removeRecursively());
        QVERIFY(writeFile(outside + "/old4.tmp", QByteArray(10, 'e')));
        age(outside + "/old4.tmp", 72);
        QVERIFY(QFile::link(outside, root + "/troca"));
#endif
        // A file held open without delete sharing (Windows) stays.
#ifdef _WIN32
        QFile held(root + "/old1.tmp");
        QVERIFY(held.open(QIODevice::ReadOnly));
#endif
        const CleanResult r = cleanTemp(plan);
#ifdef _WIN32
        held.close();
        QCOMPARE(r.inUse, 1);
        QCOMPARE(r.deleted, 3);   // old2, old3, old4
        QCOMPARE(r.changed, 1);   // muda.tmp
        QVERIFY(QFileInfo::exists(root + "/old1.tmp"));
#else
        QCOMPARE(r.inUse, 0);
        QCOMPARE(r.deleted, 3);   // old1, old2, old3
        QCOMPARE(r.changed, 2);   // muda.tmp and the file behind the swapped folder
        QVERIFY(!QFileInfo::exists(root + "/old1.tmp"));
        QVERIFY(QFileInfo::exists(outside + "/old4.tmp"));   // user data behind the link: untouched
        QVERIFY(QFileInfo(root + "/save-link").isSymbolicLink());
#endif
        QVERIFY(QFileInfo::exists(root + "/recente.tmp"));
        QVERIFY(QFileInfo::exists(root + "/muda.tmp"));
        QVERIFY(QFileInfo::exists(outside + "/save.dat"));
        QVERIFY(!QFileInfo::exists(root + "/instalador"));    // emptied old folders removed
        QVERIFY(QFileInfo::exists(root));
        QCOMPARE(r.dirsRemoved, 2);
        QVERIFY(r.bytesFreed >= 2300);
        QCOMPARE(toJson(r).value("deleted").toInt(), r.deleted);

        // Running the same plan again deletes nothing more.
        const CleanResult again = cleanTemp(plan);
        QCOMPARE(again.deleted, 0);
    }

    void defaultFoldersAreTheUsersTempAndTheProgramsOwn() {
        QTemporaryDir data;
        const QStringList roots = defaultTempRoots(data.path());
        QVERIFY(roots.contains(QDir(data.path()).filePath(QStringLiteral("temp"))));
#ifdef _WIN32
        QCOMPARE(roots.size(), 2);
        QVERIFY(QFileInfo(roots.first()).isDir());
#else
        QCOMPARE(roots.size(), 1);   // the shared /tmp is left alone outside Windows
#endif
    }
};

QTEST_GUILESS_MAIN(TestSysopt)
#include "tst_sysopt.moc"
