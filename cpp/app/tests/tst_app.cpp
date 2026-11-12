// Tests of the desktop application (offscreen). Driven by pytest (tests/ui/test_native_app.py), which
// builds real signed packages and a trusted key with the Python publisher tools and sets:
//   GK_PYTHON, GK_REPO              development helper (python -I gamekernel/helper/entry.py)
//   GK_TEST_KEY                     trusted public key (.pub)
//   GK_TEST_PKG_V0/V1/V2            packages 2026.11.10.1 / 2026.11.12.1 / 2026.11.13.1 signed by that key
//   GK_SCREENSHOT_DIR (optional)    where window screenshots are written
#include "app_context.hpp"
#include "main_window.hpp"
#include "pages/helper_pages.hpp"
#include "pages/updates_page.hpp"
#include "ui_kit.hpp"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QtTest>

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

    std::unique_ptr<Env> makeEnv(bool withBuiltinKey = true) {
        auto env = std::make_unique<Env>();
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

    void mainWindowNavigationNotificationsAndScreenshots() {
        auto env = makeEnv();
        MainWindow window(env->ctx.get());
        window.resize(1280, 820);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        QCOMPARE(window.pageCount(), 3);
        QCOMPARE(window.currentTitle(), QStringLiteral("Central de Atualização Offline"));

        QSignalSpy done(window.updatesPage(), &UpdatesPage::operationFinished);
        window.updatesPage()->importPackage(qEnvironmentVariable("GK_TEST_PKG_V1"));
        QVERIFY(waitFinished(done));
        QVERIFY(window.toasts()->visibleCount() >= 1);
        QVERIFY(window.toasts()->history().last().contains(QStringLiteral("2026.11.12.1")));
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("01-atualizacoes.png"));

        window.showPage(1);
        QCOMPARE(window.currentTitle(), QStringLiteral("Análise comportamental"));
        // The availability check starts when the window is built; it may already be done.
        QTRY_VERIFY_WITH_TIMEOUT(!window.sandboxPage()->availabilityReason().isEmpty(), 30000);
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("02-sandbox.png"));

        window.showPage(2);
        QCOMPARE(window.currentTitle(), QStringLiteral("Privacidade e rede"));
        QSignalSpy selfTest(window.privacyPage(), &PrivacyPage::selfTestFinished);
        window.privacyPage()->runNetworkSelfTest();
        QVERIFY(waitFinished(selfTest));
        QTest::qWait(200);
        screenshot(&window, QStringLiteral("03-privacidade.png"));
        env->ctx->helper()->stop();
    }
};

QTEST_MAIN(TestApp)
#include "tst_app.moc"
