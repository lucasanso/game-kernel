#include "app_context.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QMessageBox>
#include <QPushButton>
#include <QSaveFile>
#include <QStandardPaths>

namespace gk::app {

AppContext::AppContext(QString dataDir, QString resourceDir, gk::ipc::HelperConfig helperConfig, QObject* parent)
    : QObject(parent), dataDir_(std::move(dataDir)), resourceDir_(std::move(resourceDir)),
      helper_(new gk::ipc::HelperClient(std::move(helperConfig), this)) {
    QDir().mkpath(dataDir_);
    confirm = [](QWidget* parent, const QString& title, const QString& text) {
        QMessageBox box(QMessageBox::Question, title, text, QMessageBox::NoButton, parent);
        auto* yes = box.addButton(QStringLiteral("Confirmar"), QMessageBox::AcceptRole);
        box.addButton(QStringLiteral("Cancelar"), QMessageBox::RejectRole);
        box.exec();
        return box.clickedButton() == yes;
    };
}

QString AppContext::defaultDataDir(const QString& appDir) {
    const QString override = qEnvironmentVariable("GAMEKERNEL_DATA_DIR");
    if (!override.isEmpty()) return QDir(override).absolutePath();
    if (QFileInfo::exists(QDir(appDir).filePath(QStringLiteral("portable.flag"))))
        return QDir(appDir).filePath(QStringLiteral("data"));
#if defined(Q_OS_WIN)
    QString local = qEnvironmentVariable("LOCALAPPDATA");
    if (local.isEmpty()) local = QDir::home().filePath(QStringLiteral("AppData/Local"));
    return QDir(local).filePath(QStringLiteral("GameKernel"));
#else
    QString xdg = qEnvironmentVariable("XDG_DATA_HOME");
    if (xdg.isEmpty()) xdg = QDir::home().filePath(QStringLiteral(".local/share"));
    return QDir(xdg).filePath(QStringLiteral("game-kernel"));
#endif
}

QString AppContext::signaturesRoot() const { return QDir(dataDir_).filePath(QStringLiteral("signatures")); }
QString AppContext::userKeysDir() const { return QDir(dataDir_).filePath(QStringLiteral("trusted_keys")); }
QString AppContext::builtinKeysDir() const { return QDir(resourceDir_).filePath(QStringLiteral("signatures/keys")); }

QJsonObject AppContext::settings() const {
    QFile f(QDir(dataDir_).filePath(QStringLiteral("settings.json")));
    if (!f.open(QIODevice::ReadOnly) || f.size() > 4 * 1024 * 1024) return {};
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    return doc.isObject() ? doc.object() : QJsonObject{};
}

QJsonValue AppContext::setting(const QString& dotted, const QJsonValue& fallback) const {
    QJsonValue node = settings();
    for (const QString& part : dotted.split('.')) {
        if (!node.isObject() || !node.toObject().contains(part)) return fallback;
        node = node.toObject().value(part);
    }
    return node;
}

namespace {
QJsonObject withValue(QJsonObject obj, QStringList parts, const QJsonValue& value) {
    const QString key = parts.takeFirst();
    if (parts.isEmpty()) obj.insert(key, value);
    else obj.insert(key, withValue(obj.value(key).toObject(), parts, value));
    return obj;
}
}  // namespace

bool AppContext::setSetting(const QString& dotted, const QJsonValue& value, QString* error) {
    const QJsonObject updated = withValue(settings(), dotted.split('.'), value);
    QSaveFile f(QDir(dataDir_).filePath(QStringLiteral("settings.json")));
    if (!f.open(QIODevice::WriteOnly) || f.write(QJsonDocument(updated).toJson(QJsonDocument::Indented)) < 0 ||
        !f.commit()) {
        if (error) *error = f.errorString();
        return false;
    }
    return true;
}

std::unique_ptr<gk::updates::Installer> AppContext::makeInstaller() const {
    QStringList problems;
    auto keys = gk::updates::loadTrustedKeys(trustedKeyDirs(), &problems);
    return std::make_unique<gk::updates::Installer>(signaturesRoot(), std::move(keys), appVersion());
}

bool AppContext::ask(QWidget* parent, const QString& title, const QString& text) const {
    return confirm ? confirm(parent, title, text) : false;
}

}  // namespace gk::app
