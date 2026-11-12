// Game Kernel desktop application (Qt 6 Widgets, C++20).
#include "app_context.hpp"
#include "main_window.hpp"
#include "ui_kit.hpp"

#include <QApplication>
#include <QDir>
#include <QFileInfo>
#include <QLockFile>
#include <QMessageBox>
#include <QStandardPaths>

using namespace gk::app;

namespace {

// Installed/portable layout: <app>/helper/gk-helper(.exe). Development: GK_DEV_REPO (repository root) and
// GK_DEV_PYTHON (or python3/python on PATH, resolved to an absolute path). Without either, helper-backed
// pages report the helper as unavailable — nothing is faked.
gk::ipc::HelperConfig helperConfig(const QString& appDir, const QString& dataDir) {
    auto installed = gk::ipc::HelperConfig::forInstallation(appDir, dataDir);
    if (QFileInfo::exists(installed.program)) return installed;
    const QString repo = qEnvironmentVariable("GK_DEV_REPO");
    if (!repo.isEmpty()) {
        QString python = qEnvironmentVariable("GK_DEV_PYTHON");
        if (python.isEmpty()) python = QStandardPaths::findExecutable(QStringLiteral("python3"));
        if (python.isEmpty()) python = QStandardPaths::findExecutable(QStringLiteral("python"));
        if (!python.isEmpty()) return gk::ipc::HelperConfig::forDevelopment(python, repo, dataDir);
    }
    return installed;   // missing program → helper_unavailable with an explicit reason
}

}  // namespace

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(AppContext::productName());
    QApplication::setApplicationVersion(AppContext::appVersion());
    QApplication::setOrganizationName(AppContext::productName());
    applyTheme();

    const QString appDir = QCoreApplication::applicationDirPath();
    const QString dataDir = AppContext::defaultDataDir(appDir);
    QDir().mkpath(dataDir);

    // One instance at a time: two instances would install signatures or quarantine files concurrently.
    QLockFile lock(QDir(dataDir).filePath(QStringLiteral(".app.lock")));
    lock.setStaleLockTime(0);
    if (!lock.tryLock(200)) {
        QMessageBox::information(nullptr, AppContext::productName(),
                                 QStringLiteral("O Game Kernel já está aberto neste computador."));
        return 0;
    }

    AppContext ctx(dataDir, appDir, helperConfig(appDir, dataDir));
    MainWindow window(&ctx);
    window.show();
    const int code = app.exec();
    ctx.helper()->stop();
    return code;
}
