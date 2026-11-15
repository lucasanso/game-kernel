// Tests of the desktop application (offscreen). Driven by pytest (tests/ui/test_native_app.py), which
// builds real signed packages and a trusted key with the Python publisher tools and sets:
//   GK_PYTHON, GK_REPO              development helper (python -I gamekernel/helper/entry.py)
//   GK_TEST_KEY                     trusted public key (.pub)
//   GK_TEST_PKG_V0/V1/V2            packages 2026.11.10.1 / 2026.11.12.1 / 2026.11.13.1 signed by that key
//   GK_SCREENSHOT_DIR (optional)    where window screenshots are written
#include "app_context.hpp"
#include "main_window.hpp"
#include "pages/dashboard_page.hpp"
#include "pages/helper_pages.hpp"
#include "pages/history_page.hpp"
#include "pages/quarantine_page.hpp"
#include "pages/realtime_page.hpp"
#include "pages/results_page.hpp"
#include "pages/scan_page.hpp"
#include "pages/reports_page.hpp"
#include "pages/settings_page.hpp"
#include "pages/updates_page.hpp"
#include "ui_kit.hpp"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QImage>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSignalSpy>
#include <QSystemTrayIcon>
#include <QTemporaryDir>
#include <QtTest>

#include <algorithm>
#include <memory>

using namespace gk::app;

class TestApp : public QObject {
    Q_OBJECT

    struct Env {
        QTemporaryDir data;
        QTemporaryDir resources;
        std::unique_ptr<AppContext> ctx;
        QStringList asked;
        bool answer = true;
        bool answerDowngrade = true;
    };

    std::unique_ptr<Env> makeEnv(bool withBuiltinKey = true, bool withScans = false) {
        auto env = std::make_unique<Env>();
        if (withScans)   // database with a realistic scan, written by the Python data layer (GK_TEST_DB)
            QFile::copy(qEnvironmentVariable("GK_TEST_DB"), QDir(env->data.path()).filePath(QStringLiteral("gamekernel.db")));
        if (withBuiltinKey) {
            QDir(env->resources.path()).mkpath(QStringLiteral("signatures/keys"));
            QFile::copy(qEnvironmentVariable("GK_TEST_KEY"),
                        QDir(env->resources.path()).filePath(QStringLiteral("signatures/keys/release.pub")));
        }
        auto cfg = gk::ipc::HelperConfig::forDevelopment(qEnvironmentVariable("GK_PYTHON"), qEnvironmentVariable("GK_REPO"),
                                                         env->data.path());
        env->ctx = std::make_unique<AppContext>(env->data.path(), env->resources.path(), cfg);
        Env* raw = env.get();
        env->ctx->confirm = [raw](QWidget*, const QString& title, const QString&) {
            raw->asked << title;
            if (title.contains(QStringLiteral("mais antiga"))) return raw->answerDowngrade;
            return raw->answer;
        };
        return env;
    }

    // A game folder with the EICAR test file (assembled at run time) and a harmless configuration file.
    static QString makeGame(const QTemporaryDir& dir) {
        const QString game = QDir(dir.path()).filePath(QStringLiteral("MeuJogo"));
        QDir().mkpath(game);
        QFile eicar(QDir(game).filePath(QStringLiteral("leia_eicar.com")));
        if (eicar.open(QIODevice::WriteOnly))
            eicar.write(QByteArray("X5O!P%@AP[4\\PZX54(P^)7CC)7}$") + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*");
        QFile ini(QDir(game).filePath(QStringLiteral("config.ini")));
        if (ini.open(QIODevice::WriteOnly)) ini.write("[video]\nfullscreen=1\n");
        return game;
    }

    static bool waitFinished(QSignalSpy& spy, int ms = 30000) {
        return spy.count() > 0 || spy.wait(ms);
    }

    void screenshot(QWidget* w, const QString& name) {
        const QString dir = qEnvironmentVariable("GK_SCREENSHOT_DIR");
        if (dir.isEmpty()) return;
        QDir().mkpath(dir);
        QVERIFY(w->grab().save(QDir(dir).filePath(name)));
    }

private slots:
    void initTestCase() {
        applyTheme();
        QVERIFY2(!qEnvironmentVariable("GK_TEST_KEY").isEmpty(), "execute via pytest (tests/ui/test_native_app.py)");
    }

    void themeAndIcons() {
        for (const QString& name : iconNames()) QVERIFY2(!icon(name).isNull(), qPrintable(name));
        QVERIFY(icon(QStringLiteral("does-not-exist")).isNull());
        QVERIFY(!appIcon().isNull());
        // The logo really comes from the compiled-in assets/gamekernel.svg: opaque shield rim, transparent corner.
        const QImage logo = appIcon().pixmap(64, 64).toImage();
        QCOMPARE(logo.width(), 64);
        QVERIFY(qAlpha(logo.pixel(32, 6)) > 200);
        QCOMPARE(qAlpha(logo.pixel(2, 2)), 0);
        QVERIFY(QRegularExpression(QStringLiteral("^\\d+\\.\\d+\\.\\d+$")).match(AppContext::appVersion()).hasMatch());
        QVERIFY(styleSheet().contains(QStringLiteral("QFrame#card")));
        QCOMPARE(riskColor(QStringLiteral("CRITICAL")), palette::Critical);
        QCOMPARE(riskLabel(QStringLiteral("medium")), QStringLiteral("Médio"));
    }

    void dataDirAndSettings() {
        QTemporaryDir dir;
        qputenv("GAMEKERNEL_DATA_DIR", dir.path().toUtf8());
        QCOMPARE(AppContext::defaultDataDir(QStringLiteral("/nowhere")), QDir(dir.path()).absolutePath());
        qunsetenv("GAMEKERNEL_DATA_DIR");
        QTemporaryDir app;
        QFile flag(QDir(app.path()).filePath(QStringLiteral("portable.flag")));
        QVERIFY(flag.open(QIODevice::WriteOnly));
        flag.close();
        QCOMPARE(AppContext::defaultDataDir(app.path()), QDir(app.path()).filePath(QStringLiteral("data")));

        auto env = makeEnv();
        QFile f(QDir(env->data.path()).filePath(QStringLiteral("settings.json")));
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write(R"({"version": 1, "scan": {"max_workers": 3}, "sandbox": {"enabled": false, "timeout_seconds": 90}})");
        f.close();
        QVERIFY(env->ctx->setSetting(QStringLiteral("sandbox.enabled"), true));
        QCOMPARE(env->ctx->setting(QStringLiteral("sandbox.enabled")).toBool(), true);
        QCOMPARE(env->ctx->setting(QStringLiteral("sandbox.timeout_seconds")).toInt(), 90);   // untouched
        QCOMPARE(env->ctx->setting(QStringLiteral("scan.max_workers")).toInt(), 3);           // untouched
        QCOMPARE(env->ctx->setting(QStringLiteral("missing.key"), 7).toInt(), 7);
    }

    void updatesInstallDowngradeAndRollback() {
        auto env = makeEnv();
        UpdatesPage page(env->ctx.get());
        QVERIFY(page.activeVersion().isEmpty());
        QVERIFY(page.stale());
        QSignalSpy done(&page, &UpdatesPage::operationFinished);

        page.importPackage(qEnvironmentVariable("GK_TEST_PKG_V1"));
        QVERIFY(waitFinished(done));
        QCOMPARE(done.takeFirst().at(0).toBool(), true);
        QCOMPARE(page.activeVersion(), QStringLiteral("2026.11.12.1"));
        QVERIFY(env->asked.contains(QStringLiteral("Instalar atualização offline")));

        page.importPackage(qEnvironmentVariable("GK_TEST_PKG_V2"));
        QVERIFY(waitFinished(done));
        QCOMPARE(done.takeFirst().at(0).toBool(), true);
        QCOMPARE(page.activeVersion(), QStringLiteral("2026.11.13.1"));

        // Older package: the user is asked explicitly and declines → nothing changes.
        env->answerDowngrade = false;
        page.importPackage(qEnvironmentVariable("GK_TEST_PKG_V0"));
        QVERIFY(waitFinished(done));
        const auto refused = done.takeFirst();
        QCOMPARE(refused.at(0).toBool(), false);
        QCOMPARE(refused.at(1).toString(), QStringLiteral("downgrade"));
        QVERIFY(env->asked.contains(QStringLiteral("Instalar versão mais antiga?")));
        QCOMPARE(page.activeVersion(), QStringLiteral("2026.11.13.1"));

        page.rollbackToPrevious();
        QVERIFY(waitFinished(done));
        QCOMPARE(done.takeFirst().at(0).toBool(), true);
        QCOMPARE(page.activeVersion(), QStringLiteral("2026.11.12.1"));
    }

    void updatesRejectsBadInputAndRespectsDecline() {
        auto env = makeEnv();
        UpdatesPage page(env->ctx.get());
        QSignalSpy done(&page, &UpdatesPage::operationFinished);
        QTemporaryDir dir;
        const QString junk = QDir(dir.path()).filePath(QStringLiteral("junk.gkpkg"));
        QFile f(junk);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write("PK\x03\x04 not a game kernel package");
        f.close();
        page.importPackage(junk);
        QVERIFY(waitFinished(done));
        QCOMPARE(done.takeFirst().at(1).toString(), QStringLiteral("not_a_package"));

        env->answer = false;   // the user declines after seeing the verified details
        page.importPackage(qEnvironmentVariable("GK_TEST_PKG_V1"));
        QVERIFY(waitFinished(done));
        QCOMPARE(done.takeFirst().at(1).toString(), QStringLiteral("cancelled"));
        QVERIFY(page.activeVersion().isEmpty());
    }

    void untrustedPublisherUntilKeyIsAdded() {
        auto env = makeEnv(/*withBuiltinKey=*/false);
        UpdatesPage page(env->ctx.get());
        QSignalSpy done(&page, &UpdatesPage::operationFinished);
        page.importPackage(qEnvironmentVariable("GK_TEST_PKG_V1"));
        QVERIFY(waitFinished(done));
        QCOMPARE(done.takeFirst().at(1).toString(), QStringLiteral("no_trusted_keys"));

        QTemporaryDir dir;
        const QString junk = QDir(dir.path()).filePath(QStringLiteral("bad.pub"));
        QFile f(junk);
        QVERIFY(f.open(QIODevice::WriteOnly));
        f.write("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n");
        f.close();
        QVERIFY(!page.addTrustedKey(junk));
        QVERIFY(page.addTrustedKey(qEnvironmentVariable("GK_TEST_KEY")));
        QVERIFY(env->asked.contains(QStringLiteral("Confiar nesta chave?")));
        const auto keys = gk::updates::loadTrustedKeys({env->ctx->userKeysDir()});
        QCOMPARE(int(keys.size()), 1);

        page.importPackage(qEnvironmentVariable("GK_TEST_PKG_V1"));
        QVERIFY(waitFinished(done));
        QCOMPARE(done.takeFirst().at(0).toBool(), true);

        QVERIFY(page.removeTrustedKey(keys.front().id));
        QVERIFY(gk::updates::loadTrustedKeys({env->ctx->userKeysDir()}).empty());
    }

    void builtinKeysCannotBeRemoved() {
        auto env = makeEnv();
        UpdatesPage page(env->ctx.get());
        const auto builtin = gk::updates::loadTrustedKeys({env->ctx->builtinKeysDir()});
        QCOMPARE(int(builtin.size()), 1);
        QVERIFY(!page.removeTrustedKey(builtin.front().id));
        QVERIFY(QFile::exists(builtin.front().source));
    }

    void sandboxRefusesWithoutIsolation() {
        auto env = makeEnv();
        SandboxPage page(env->ctx.get());
        QSignalSpy checked(&page, &SandboxPage::availabilityChecked);
        QVERIFY(waitFinished(checked));
#if !defined(Q_OS_WIN)
        QCOMPARE(checked.takeFirst().at(0).toBool(), false);
        QVERIFY(page.availabilityReason().contains(QStringLiteral("Windows")));
#endif
        page.setSample(qEnvironmentVariable("GK_TEST_KEY"));
        if (!page.available()) QVERIFY(!page.canAnalyze());
        page.analyze();   // must be a no-op without isolation
        QVERIFY(!env->asked.contains(QStringLiteral("Análise comportamental")) || page.available());
    }

    void privacySelfTestThroughRealHelper() {
        auto env = makeEnv();
        PrivacyPage page(env->ctx.get());
        QSignalSpy helper(&page, &PrivacyPage::helperChecked);
        QVERIFY(waitFinished(helper));
        QCOMPARE(helper.takeFirst().at(0).toBool(), true);   // helper up, netguard active
        QSignalSpy selfTest(&page, &PrivacyPage::selfTestFinished);
        page.runNetworkSelfTest();
        QVERIFY(waitFinished(selfTest));
        QCOMPARE(selfTest.takeFirst().at(0).toBool(), true);
        QCOMPARE(page.lastSelfTestVerdict(), QStringLiteral("ok"));
        env->ctx->helper()->stop();
    }

    void reportsFromTheRealDatabase() {
        auto env = makeEnv(true, true);
        const qint64 scanId = qEnvironmentVariable("GK_TEST_SCAN_ID").toLongLong();
        const QString db = QDir(env->data.path()).filePath(QStringLiteral("gamekernel.db"));
        const QDateTime dbTime = QFileInfo(db).lastModified();
        ReportsPage page(env->ctx.get());
        QSignalSpy loaded(&page, &ReportsPage::scansLoaded);
        QVERIFY(waitFinished(loaded));
        QVERIFY(page.scanCount() >= 1);
        QVERIFY(page.emptyStateText().isEmpty());
        QVERIFY(page.selectScan(scanId));
        QCOMPARE(page.selectedScan(), scanId);
        QVERIFY(!page.selectScan(987654));                       // unknown scans are not selectable

        QSignalSpy finished(&page, &ReportsPage::reportFinished);
        QVERIFY(page.generate());
        QVERIFY(waitFinished(finished, 120000));
        const auto result = finished.takeFirst();
        QVERIFY2(result.at(0).toBool(), qPrintable(result.at(1).toString()));
        const QStringList files = page.generatedFiles();
        QVERIFY2(files.size() >= 2, qPrintable(files.join(',')));
        QVERIFY(std::any_of(files.begin(), files.end(), [](const QString& f) { return f.endsWith(QStringLiteral(".html")); }));
        QVERIFY(std::any_of(files.begin(), files.end(), [](const QString& f) { return f.endsWith(QStringLiteral(".json")); }));
        for (const QString& f : files) QVERIFY(QFileInfo(QDir(page.reportsDir()).filePath(f)).size() > 0);
        QCOMPARE(QFileInfo(db).lastModified(), dbTime);          // the database was only read
        env->ctx->helper()->stop();
    }

    void reportsOnAFreshInstallation() {
        auto env = makeEnv();
        ReportsPage page(env->ctx.get());
        QSignalSpy loaded(&page, &ReportsPage::scansLoaded);
        QVERIFY(waitFinished(loaded));
        QCOMPARE(page.scanCount(), 0);
        QVERIFY(page.emptyStateText().contains(QStringLiteral("gk-cli")));
        QVERIFY(!page.generate());                               // nothing selected: nothing is sent
        QVERIFY(!QFileInfo::exists(QDir(env->data.path()).filePath(QStringLiteral("gamekernel.db"))));
        env->ctx->helper()->stop();
    }

    void settingsAreValidatedSharedAndReadByTheHelper() {
        auto env = makeEnv();
        QVERIFY(env->ctx->setSetting(QStringLiteral("scan.max_workers"), 3));     // a key this page does not own
        SettingsPage settings(env->ctx.get());
        SandboxPage sandbox(env->ctx.get());
        QSignalSpy checked(&sandbox, &SandboxPage::availabilityChecked);
        QVERIFY(waitFinished(checked));

        QVERIFY(settings.setRedactUsername(false));
        QVERIFY(settings.setIncludeHostname(true));
        QVERIFY(settings.setStaleAfterDays(30));
        QVERIFY(!settings.setStaleAfterDays(0));                                  // config.py range 1..365
        QVERIFY(settings.lastError().contains(QStringLiteral("365")));
        QVERIFY(!settings.setSandboxTimeout(10));                                 // 30..1800
        QVERIFY(settings.setSandboxTimeout(600));
        QVERIFY(settings.setSandboxEnabled(true));
        QVERIFY(!settings.setSysmonPath(QDir(env->data.path()).filePath(QStringLiteral("nao-existe.exe"))));
        QTemporaryDir tools;
        const QString sysmon = QDir(tools.path()).filePath(QStringLiteral("Sysmon64.exe"));
        { QFile f(sysmon); QVERIFY(f.open(QIODevice::WriteOnly)); f.write("MZ"); }
        const QString impostor = QDir(tools.path()).filePath(QStringLiteral("ferramenta.exe"));
        { QFile f(impostor); QVERIFY(f.open(QIODevice::WriteOnly)); f.write("MZ"); }
        QVERIFY(!settings.setSysmonPath(impostor));                               // manager.py accepts only Sysmon
        QVERIFY(settings.setSysmonPath(sysmon));

        const auto& ctx = *env->ctx;
        QCOMPARE(ctx.setting(QStringLiteral("reports.redact_username")).toBool(), false);
        QCOMPARE(ctx.setting(QStringLiteral("reports.include_hostname")).toBool(), true);
        QCOMPARE(ctx.setting(QStringLiteral("updates.stale_after_days")).toInt(), 30);
        QCOMPARE(ctx.setting(QStringLiteral("sandbox.timeout_seconds")).toInt(), 600);
        QCOMPARE(ctx.setting(QStringLiteral("sandbox.sysmon_path")).toString(), QFileInfo(sysmon).absoluteFilePath());
        QCOMPARE(ctx.setting(QStringLiteral("scan.max_workers")).toInt(), 3);     // preserved
        QVERIFY(sandbox.analysisEnabled());                                       // the sandbox page followed the switch

        // The Python helper reads the file written by the C++ page (gamekernel/config.py validation included).
        const auto availability = env->ctx->helper()->callBlocking(QStringLiteral("sandbox.availability"));
        QVERIFY2(availability.ok, qPrintable(availability.error.message));
        QCOMPARE(availability.value.toObject().value("enabled_in_settings").toBool(), true);

        env->answer = false;
        QVERIFY(!settings.restoreDefaults());                                     // declined: nothing changes
        QCOMPARE(ctx.setting(QStringLiteral("sandbox.enabled")).toBool(), true);
        env->answer = true;
        QVERIFY(settings.restoreDefaults());
        QCOMPARE(ctx.setting(QStringLiteral("sandbox.enabled")).toBool(), false);
        QVERIFY(!sandbox.analysisEnabled());
        QCOMPARE(ctx.setting(QStringLiteral("updates.stale_after_days")).toInt(), 7);
        QCOMPARE(ctx.setting(QStringLiteral("reports.redact_username")).toBool(), true);
        QCOMPARE(ctx.setting(QStringLiteral("sandbox.sysmon_path")).toString(), QString());
        QCOMPARE(ctx.setting(QStringLiteral("scan.max_workers")).toInt(), 3);
        QVERIFY(QFileInfo::exists(sysmon));                                       // forgetting never deletes the file
        env->ctx->helper()->stop();
    }

    void privacyShowsServicesThatFailedToLoad() {
        auto env = std::make_unique<Env>();
        auto cfg = gk::ipc::HelperConfig::forDevelopment(qEnvironmentVariable("GK_PYTHON"), qEnvironmentVariable("GK_REPO"),
                                                         env->data.path());
        cfg.arguments = {QStringLiteral("-I"),
                         QDir(qEnvironmentVariable("GK_REPO")).filePath(QStringLiteral("tests/helper/fault_helper.py")),
                         QStringLiteral("--unavailable-service")};
        env->ctx = std::make_unique<AppContext>(env->data.path(), env->resources.path(), cfg);
        PrivacyPage page(env->ctx.get());
        QSignalSpy checked(&page, &PrivacyPage::helperChecked);
        QVERIFY(waitFinished(checked));
        QCOMPARE(page.unavailableServices(), QStringList{QStringLiteral("gamekernel.helper.services.sandbox")});
        QVERIFY(page.helperStatus().contains(QStringLiteral("indisponíveis")));
        env->ctx->helper()->stop();
    }

    void corePagesAgainstTheRealCore() {
        auto env = makeEnv();
        QTemporaryDir games;
        const QString game = makeGame(games);
        const QString eicarPath = QDir(game).filePath(QStringLiteral("leia_eicar.com"));
        QFile original(eicarPath);
        QVERIFY(original.open(QIODevice::ReadOnly));
        const QByteArray eicarBytes = original.readAll();
        original.close();

        // Scan (isolated workers; the page only reads)
        ScanPage scan(env->ctx.get());
        QVERIFY(!scan.start());                                       // nothing to scan yet
        scan.addTarget(game);
        scan.addTarget(game);                                         // duplicates ignored
        QCOMPARE(scan.targets().size(), 1);
        QSignalSpy finished(&scan, &ScanPage::scanFinished);
        QVERIFY(scan.start());
        QVERIFY(!scan.start());                                       // one scan at a time
        QVERIFY(waitFinished(finished, 180000));
        const QJsonObject summary = finished.first().at(0).toJsonObject();
        QVERIFY2(summary.value("status").toString() == QLatin1String("completed"),
                 qPrintable(QString::fromUtf8(QJsonDocument(summary).toJson(QJsonDocument::Compact))));
        const qint64 scanId = summary.value("scan_id").toInteger();
        QVERIFY(scanId > 0);
        QVERIFY(scan.findingsCount() >= 1);

        // History and dashboard read the same database
        HistoryPage history(env->ctx.get());
        QSignalSpy historyLoaded(&history, &HistoryPage::loaded);
        QVERIFY(waitFinished(historyLoaded));
        QCOMPARE(history.scanCount(), 1);
        QCOMPARE(history.selectedScan(), scanId);
        DashboardPage dashboard(env->ctx.get());
        QSignalSpy refreshed(&dashboard, &DashboardPage::refreshed);
        QVERIFY(waitFinished(refreshed, 60000));
        QVERIFY2(dashboard.lastScanText().contains(QStringLiteral("ameaça")), qPrintable(dashboard.lastScanText()));
        QCOMPARE(dashboard.integrityStatus(), QStringLiteral("Sem manifesto"));   // development build
        QCOMPARE(dashboard.quarantineText(), QStringLiteral("Vazia"));

        // Forensic analysis: what, where, why, what to do
        ResultsPage results(env->ctx.get());
        QSignalSpy loaded(&results, &ResultsPage::loaded);
        results.loadScan(scanId);
        QVERIFY(waitFinished(loaded));
        QVERIFY(results.findingsCount() >= 1);
        QVERIFY(results.selectFile(QStringLiteral("leia_eicar.com")));
        const QString detail = results.detailText();
        for (const char* expected : {"Caminho", "SHA-256", "Por que", "O que fazer"})
            QVERIFY2(detail.contains(QString::fromUtf8(expected)), qPrintable(detail));
        results.setFilter(QStringLiteral("pua"));
        QCOMPARE(results.findingsCount(), 0);
        results.setFilter(QStringLiteral("malware"));
        QVERIFY(results.selectFile(QStringLiteral("leia_eicar.com")));

        // Quarantine from the analysis: declined first, then confirmed
        QSignalSpy quarantined(&results, &ResultsPage::quarantineFinished);
        env->answer = false;
        QVERIFY(!results.quarantineSelected());
        QVERIFY(QFileInfo::exists(eicarPath));
        env->answer = true;
        QVERIFY(results.quarantineSelected());
        QVERIFY(waitFinished(quarantined, 60000));
        QVERIFY2(quarantined.first().at(0).toBool(), qPrintable(quarantined.first().at(1).toString()));
        QVERIFY(!QFileInfo::exists(eicarPath));

        // Quarantine page: list, restore to the original place (content checked), verify the vault
        QuarantinePage quarantine(env->ctx.get());
        QSignalSpy listed(&quarantine, &QuarantinePage::listed);
        QVERIFY(waitFinished(listed, 60000));
        QCOMPARE(quarantine.itemCount(), 1);
        QSignalSpy op(&quarantine, &QuarantinePage::operationFinished);
        env->answer = false;
        QVERIFY(!quarantine.restoreSelected());                      // declined: nothing sent
        env->answer = true;
        QVERIFY(quarantine.restoreSelected());
        QVERIFY(waitFinished(op, 60000));
        QCOMPARE(op.first().at(0).toString(), QStringLiteral("restore"));
        QVERIFY2(op.first().at(1).toBool(), qPrintable(op.first().at(2).toString()));
        QFile back(eicarPath);
        QVERIFY(back.open(QIODevice::ReadOnly));
        QCOMPARE(back.readAll(), eicarBytes);
        op.clear();
        quarantine.verifyVault();
        QVERIFY(waitFinished(op, 60000));
        QCOMPARE(op.first().at(0).toString(), QStringLiteral("verify"));
        QVERIFY(op.first().at(1).toBool());
        env->ctx->helper()->stop();
    }

    void realtimePageAgainstTheRealMonitor() {
        auto env = makeEnv();
        RealtimePage page(env->ctx.get());
        QSignalSpy shown(&page, &RealtimePage::statusShown);
        QVERIFY(page.statusText().startsWith(QStringLiteral("Desativada")));
        QVERIFY(!page.setProtectionEnabled(true));                    // nothing to watch yet
        QVERIFY(page.lastError().contains(QStringLiteral("pasta")));
        QTemporaryDir games;
        QVERIFY(!page.addFolder(QDir(games.path()).filePath(QStringLiteral("nao-existe"))));
        QVERIFY(!page.addFolder(env->data.path()));                   // the program's own data is never watched
        QVERIFY(page.addFolder(games.path()));
        QVERIFY(!page.addFolder(games.path()));                       // already listed
        QCOMPARE(page.folders().size(), 1);
        QVERIFY(!page.setBatchSeconds(1));
        QVERIFY(page.setBatchSeconds(2));
        QVERIFY(page.setStableSeconds(1));
        QVERIFY(!page.setNotifyMinRisk(QStringLiteral("ALTO")));
        QVERIFY(page.setNotifyMinRisk(QStringLiteral("HIGH")));
        env->answer = false;
        QVERIFY(!page.setAutoQuarantine(true));                       // declined: stays off
        QCOMPARE(env->ctx->setting(QStringLiteral("realtime.auto_quarantine"), false).toBool(), false);
        // settings.json holds exactly the keys gamekernel/config.py validates
        QCOMPARE(env->ctx->setting(QStringLiteral("realtime.notify_min_risk")).toString(), QStringLiteral("HIGH"));
        QCOMPARE(env->ctx->setting(QStringLiteral("realtime.batch_seconds")).toInt(), 2);
        QCOMPARE(env->ctx->realtimeSettings().notifyMinRisk, 4);

        QVERIFY(page.setProtectionEnabled(true));
        QTRY_VERIFY_WITH_TIMEOUT(page.statusText().startsWith(QStringLiteral("Ativa")), 15000);
        QVERIFY2(page.folderState(0).endsWith(QStringLiteral("observada")), qPrintable(page.folderState(0)));
        QFile sample(QDir(games.path()).filePath(QStringLiteral("trainer/leia_eicar.com")));
        QVERIFY(QDir().mkpath(QFileInfo(sample).absolutePath()));
        QVERIFY(sample.open(QIODevice::WriteOnly));
        sample.write(QByteArray("X5O!P%@AP[4\\PZX54(P^)7CC)7}$") + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*");
        sample.close();
        QTRY_VERIFY_WITH_TIMEOUT(page.eventCount() >= 1, 120000);
        QVERIFY(QFileInfo::exists(sample.fileName()));                // automatic quarantine is off
        QVERIFY2(page.statusText().contains(QStringLiteral("1 achado")), qPrintable(page.statusText()));
        QSignalSpy open(&page, &RealtimePage::openResults);
        QVERIFY(page.openSelectedEvent());
        QVERIFY(open.first().at(0).toLongLong() > 0);

        // Removing the last folder turns the protection off, so what is shown stays true.
        QVERIFY(page.removeFolder(page.folders().first()));
        QVERIFY(page.folders().isEmpty());
        QTRY_VERIFY_WITH_TIMEOUT(page.statusText().startsWith(QStringLiteral("Desativada")), 15000);
        QVERIFY(!env->ctx->realtime()->active());
        env->ctx->helper()->stop();
    }

    void mainWindowNavigationNotificationsAndScreenshots() {
        auto env = makeEnv(true, true);
        QTemporaryDir games;
        const QString game = makeGame(games);
        MainWindow window(env->ctx.get());
        window.resize(1280, 820);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        QCOMPARE(window.pageCount(), 11);
        // Without a notification area (offscreen tests) closing the window ends the program as usual.
        QVERIFY(!window.keepsRunningInTray() || QSystemTrayIcon::isSystemTrayAvailable());
        QCOMPARE(window.currentTitle(), QStringLiteral("Painel"));

        // A real scan started from the scan page, then its analysis, history and quarantine.
        window.showPage(MainWindow::Scan);
        QCOMPARE(window.currentTitle(), QStringLiteral("Segurança do jogo"));
        QSignalSpy scanned(window.scanPage(), &ScanPage::scanFinished);
        window.scanPage()->addTarget(game);
        QVERIFY(window.scanPage()->start());
        QVERIFY(waitFinished(scanned, 180000));
        const qint64 scanId = scanned.first().at(0).toJsonObject().value("scan_id").toInteger();
        QTest::qWait(300);
        screenshot(&window, QStringLiteral("02-varredura.png"));

        QSignalSpy loaded(window.resultsPage(), &ResultsPage::loaded);
        window.resultsPage()->loadScan(scanId);
        window.showPage(MainWindow::Results);
        QCOMPARE(window.currentTitle(), QStringLiteral("Análise forense"));
        QVERIFY(waitFinished(loaded));                                // results of the requested scan, not earlier content
        QCOMPARE(window.resultsPage()->scanId(), scanId);
        QVERIFY(window.resultsPage()->findingsCount() >= 1);
        QVERIFY(window.resultsPage()->selectFile(QStringLiteral("leia_eicar.com")));
        QTest::qWait(300);
        screenshot(&window, QStringLiteral("03-analise.png"));
        QSignalSpy quarantined(window.resultsPage(), &ResultsPage::quarantineFinished);
        QVERIFY(window.resultsPage()->quarantineSelected());
        QVERIFY(waitFinished(quarantined, 60000));

        window.showPage(MainWindow::History);
        QCOMPARE(window.currentTitle(), QStringLiteral("Histórico"));
        QTRY_VERIFY_WITH_TIMEOUT(window.historyPage()->scanCount() >= 2, 30000);   // Python-written scan + this one
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("04-historico.png"));

        window.showPage(MainWindow::Quarantine);
        QCOMPARE(window.currentTitle(), QStringLiteral("Quarentena"));
        QTRY_VERIFY_WITH_TIMEOUT(window.quarantinePage()->itemCount() == 1, 30000);
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("05-quarentena.png"));

        // Real-time protection on a downloads folder: a new threat is reported in the window.
        QTemporaryDir downloads;
        window.showPage(MainWindow::Realtime);
        QCOMPARE(window.currentTitle(), QStringLiteral("Proteção em tempo real"));
        RealtimePage* rt = window.realtimePage();
        QVERIFY(rt->addFolder(downloads.path()));
        QVERIFY(rt->setBatchSeconds(2));
        QVERIFY(rt->setStableSeconds(1));
        QVERIFY(rt->setProtectionEnabled(true));
        QTRY_VERIFY_WITH_TIMEOUT(rt->statusText().startsWith(QStringLiteral("Ativa")), 15000);
        QFile fresh(QDir(downloads.path()).filePath(QStringLiteral("trainer_v1.2/leia_eicar.com")));
        QVERIFY(QDir().mkpath(QFileInfo(fresh).absolutePath()));
        QVERIFY(fresh.open(QIODevice::WriteOnly));
        fresh.write(QByteArray("X5O!P%@AP[4\\PZX54(P^)7CC)7}$") + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*");
        fresh.close();
        QTRY_VERIFY_WITH_TIMEOUT(rt->eventCount() >= 1, 120000);
        QTRY_VERIFY_WITH_TIMEOUT(
            std::any_of(window.toasts()->history().begin(), window.toasts()->history().end(),
                        [](const QString& t) { return t.startsWith(QStringLiteral("Proteção em tempo real: leia_eicar.com")); }),
            10000);
        QTest::qWait(300);
        screenshot(&window, QStringLiteral("06-tempo-real.png"));

        window.showPage(MainWindow::Dashboard);
        QVERIFY2(window.dashboardPage()->realtimeText().startsWith(QStringLiteral("Ativa")), qPrintable(window.dashboardPage()->realtimeText()));
        QSignalSpy refreshed(window.dashboardPage(), &DashboardPage::refreshed);
        window.dashboardPage()->refresh();
        QVERIFY(waitFinished(refreshed, 60000));
        QVERIFY(window.dashboardPage()->quarantineText().contains(QStringLiteral("1 item")));
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("01-painel.png"));

        window.showPage(MainWindow::Updates);
        QCOMPARE(window.currentTitle(), QStringLiteral("Central de Atualização Offline"));
        QSignalSpy done(window.updatesPage(), &UpdatesPage::operationFinished);
        window.updatesPage()->importPackage(qEnvironmentVariable("GK_TEST_PKG_V1"));
        QVERIFY(waitFinished(done));
        QVERIFY(window.toasts()->visibleCount() >= 1);
        QVERIFY(window.toasts()->history().last().contains(QStringLiteral("2026.11.12.1")));
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("07-atualizacoes.png"));

        window.showPage(MainWindow::Sandbox);
        QCOMPARE(window.currentTitle(), QStringLiteral("Análise comportamental"));
        QTRY_VERIFY_WITH_TIMEOUT(!window.sandboxPage()->availabilityReason().isEmpty(), 30000);
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("08-sandbox.png"));

        window.showPage(MainWindow::Reports);
        QCOMPARE(window.currentTitle(), QStringLiteral("Relatórios forenses"));
        QTRY_VERIFY_WITH_TIMEOUT(window.reportsPage()->scanCount() >= 1, 30000);
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("09-relatorios.png"));

        window.showPage(MainWindow::Privacy);
        QCOMPARE(window.currentTitle(), QStringLiteral("Privacidade e rede"));
        QSignalSpy selfTest(window.privacyPage(), &PrivacyPage::selfTestFinished);
        window.privacyPage()->runNetworkSelfTest();
        QVERIFY(waitFinished(selfTest));
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("10-privacidade.png"));

        window.showPage(MainWindow::Settings);
        QCOMPARE(window.currentTitle(), QStringLiteral("Configurações"));
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("11-configuracoes.png"));
        env->ctx->helper()->stop();
    }
};

QTEST_MAIN(TestApp)
#include "tst_app.moc"
