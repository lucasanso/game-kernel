#include "gk/updates/installer.hpp"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLockFile>
#include <QSaveFile>
#include <QScopeGuard>
#include <QUuid>

#include <memory>

namespace gk::updates {

namespace {

const QStringList kComponentOrder{"clamav", "yara", "ioc"};
constexpr int kHistoryLimit = 50;

QString nowIso() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODate); }

InstallReport failure(InstallReport rep, const char* code, const QString& message) {
    rep.ok = false;
    rep.error = {QString::fromLatin1(code), message};
    return rep;
}

std::optional<QJsonObject> readManifest(const QString& dir) {
    QFile f(QDir(dir).filePath(QStringLiteral("manifest.json")));
    if (!f.open(QIODevice::ReadOnly)) return std::nullopt;
    const QJsonDocument doc = QJsonDocument::fromJson(f.read(4 * 1024 * 1024));
    if (!doc.isObject()) return std::nullopt;
    return doc.object();
}

bool copyFlatDir(const QString& from, const QString& to) {
    if (!QDir().mkpath(to)) return false;
    const QFileInfoList files = QDir(from).entryInfoList(QDir::Files | QDir::NoSymLinks | QDir::Hidden, QDir::Name);
    for (const QFileInfo& fi : files)
        if (!QFile::copy(fi.absoluteFilePath(), QDir(to).filePath(fi.fileName()))) return false;
    return true;
}

ComponentValidator builtinValidator(const QString& component) {
    if (component == QLatin1String("ioc")) return validateIocDir;
    if (component == QLatin1String("clamav")) return validateClamavDir;
    return validateYaraDir;
}

void appendHistory(const QString& root, const QJsonObject& entry) {
    QFile f(QDir(root).filePath(QStringLiteral("install-history.jsonl")));
    if (f.open(QIODevice::Append)) f.write(QJsonDocument(entry).toJson(QJsonDocument::Compact) + '\n');
}

}  // namespace

QJsonObject InstallReport::toJson() const {
    QJsonArray comps;
    for (const ComponentReport& c : components)
        comps.append(QJsonObject{{"component", c.component}, {"version", c.version}, {"count", double(c.count)},
                                 {"files", QJsonArray::fromStringList(c.files)},
                                 {"messages", QJsonArray::fromStringList(c.messages)}});
    QJsonObject o{{"ok", ok},
                  {"package_id", packageId},
                  {"package_version", packageVersion},
                  {"previous_package_version", previousPackageVersion},
                  {"key_id", keyId},
                  {"publisher", publisher},
                  {"components", comps},
                  {"kept_components", QJsonArray::fromStringList(keptComponents)},
                  {"details", QJsonArray::fromStringList(details)}};
    if (!ok) o.insert("error", QJsonObject{{"code", error.code}, {"message", error.message}});
    if (!activeManifest.isEmpty()) o.insert("active_manifest", activeManifest);
    return o;
}

Installer::Installer(QString signaturesRoot, std::vector<TrustedKey> keys, QString appVersion)
    : root_(QDir(signaturesRoot).absolutePath()), keys_(std::move(keys)), appVersion_(std::move(appVersion)) {}

void Installer::setValidator(const QString& component, ComponentValidator validator) {
    validators_.insert(component, std::move(validator));
}

QString Installer::activeDir() const { return QDir(root_).filePath(QStringLiteral("active")); }
QString Installer::previousDir() const { return QDir(root_).filePath(QStringLiteral("previous")); }
QString Installer::stagingDir() const { return QDir(root_).filePath(QStringLiteral("staging")); }

std::optional<QJsonObject> Installer::activeManifest() const { return readManifest(activeDir()); }

VerifyResult Installer::inspect(const QString& packagePath) const { return verifyPackage(packagePath, keys_, appVersion_); }

QStringList Installer::recoverInterrupted() {
    QStringList notes;
    QDir rootDir(root_);
    if (!QDir(activeDir()).exists() && QDir(previousDir()).exists()) {
        // Crash between "active → previous" and "staging → active": bring the old set back.
        if (rootDir.rename(previousDir(), activeDir()))
            notes << QStringLiteral("instalação interrompida desfeita: conjunto anterior restaurado");
    }
    const QFileInfoList leftovers = QDir(stagingDir()).entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QFileInfo& fi : leftovers) {
        if (fi.fileName().endsWith(QLatin1String("-rollback")) && !QDir(previousDir()).exists() &&
            QDir(activeDir()).exists()) {
            // Crash in the middle of a rollback after the swap: keep the set as "previous".
            if (rootDir.rename(fi.absoluteFilePath(), previousDir())) {
                notes << QStringLiteral("rollback interrompido concluído");
                continue;
            }
        }
        QDir(fi.absoluteFilePath()).removeRecursively();
        notes << QStringLiteral("arquivos temporários removidos: %1").arg(fi.fileName());
    }
    return notes;
}

InstallReport Installer::install(const QString& packagePath, const InstallOptions& options) {
    InstallReport rep;
    if (!QDir().mkpath(stagingDir())) return failure(rep, error_code::IoError, QStringLiteral("sem acesso a %1").arg(root_));
    QLockFile lock(QDir(root_).filePath(QStringLiteral(".install.lock")));
    lock.setStaleLockTime(30 * 60 * 1000);
    if (!lock.tryLock(3000))
        return failure(rep, error_code::Busy, QStringLiteral("outra instalação de assinaturas está em andamento"));
    rep.details += recoverInterrupted();

    const QString setDir = QDir(stagingDir()).filePath(QUuid::createUuid().toString(QUuid::WithoutBraces));
    if (!QDir().mkpath(setDir)) return failure(rep, error_code::IoError, QStringLiteral("não foi possível criar a área temporária"));
    auto cleanup = qScopeGuard([&] { QDir(setDir).removeRecursively(); });

    // ---- 1. single streaming pass: verify and extract
    std::unique_ptr<QFile> out;
    QString currentPath;
    const PayloadSink sink = [&](const FileEntry& fe, const char* data, qint64 n, bool last) -> bool {
        if (currentPath != fe.path) {
            out.reset();
            if (isReservedWindowsName(fe.name) || !QDir().mkpath(QDir(setDir).filePath(fe.component))) return false;
            out = std::make_unique<QFile>(QDir(setDir).filePath(fe.path));
            if (!out->open(QIODevice::WriteOnly | QIODevice::NewOnly)) return false;
            currentPath = fe.path;
        }
        if (n > 0 && out->write(data, n) != n) return false;
        if (last) {
            const bool flushed = out->flush();
            out->close();
            out.reset();
            currentPath.clear();
            return flushed;
        }
        return true;
    };
    const VerifyResult verified = verifyPackage(packagePath, keys_, appVersion_, sink);
    out.reset();
    if (!verified.ok) return failure(rep, verified.error.code.toLatin1().constData(), verified.error.message);
    const Manifest& m = verified.manifest;
    rep.packageId = m.packageId;
    rep.packageVersion = m.packageVersion;
    rep.keyId = verified.keyId;
    rep.publisher = m.publisher;

    // ---- 2. downgrade protection
    const std::optional<QJsonObject> current = activeManifest();
    if (current) {
        rep.previousPackageVersion = current->value("package_version").toString();
        const auto oldV = parsePackageVersion(rep.previousPackageVersion);
        const auto newV = parsePackageVersion(m.packageVersion);
        if (oldV && newV && *newV <= *oldV && !options.allowDowngrade)
            return failure(rep, error_code::Downgrade,
                           QStringLiteral("o pacote %1 não é mais novo que o instalado (%2); confirme explicitamente "
                                          "para reverter").arg(m.packageVersion, rep.previousPackageVersion));
    }

    // ---- 3. carry over components that the package does not replace
    for (const QString& comp : kComponentOrder) {
        if (m.components.contains(comp)) continue;
        const QString from = QDir(activeDir()).filePath(comp);
        if (!QDir(from).exists()) continue;
        if (!copyFlatDir(from, QDir(setDir).filePath(comp)))
            return failure(rep, error_code::IoError, QStringLiteral("falha ao preservar o componente %1").arg(comp));
        rep.keptComponents << comp;
    }

    // ---- 4. validate replaced components
    QJsonObject componentsJson;
    const QString installedAt = nowIso();
    for (const QString& comp : kComponentOrder) {
        if (!m.components.contains(comp)) {
            if (current && current->value("components").toObject().contains(comp))
                componentsJson.insert(comp, current->value("components").toObject().value(comp));
            continue;
        }
        const QString dir = QDir(setDir).filePath(comp);
        const ComponentValidator validator = validators_.value(comp, builtinValidator(comp));
        const ValidationResult vr = validator(dir);
        if (!vr.ok) {
            for (const QString& msg : vr.messages) rep.details << QStringLiteral("%1: %2").arg(comp, msg);
            return failure(rep, error_code::ValidationFailed,
                           QStringLiteral("o componente %1 não passou na validação; nada foi alterado").arg(comp));
        }
        ComponentReport cr;
        cr.component = comp;
        cr.version = m.components.value(comp).toObject().value("version").toString();
        cr.count = vr.count;
        cr.messages = vr.messages;
        QJsonObject hashes;
        for (const FileEntry& fe : m.files) {
            if (fe.component != comp) continue;
            cr.files << fe.name;
            hashes.insert(fe.name, QString::fromLatin1(fe.sha256Hex));
        }
        componentsJson.insert(comp, QJsonObject{{"version", cr.version}, {"package_id", m.packageId},
                                                {"package_version", m.packageVersion}, {"installed_at", installedAt},
                                                {"count", double(cr.count)}, {"files", QJsonArray::fromStringList(cr.files)},
                                                {"sha256", hashes}});
        rep.components.push_back(cr);
    }

    // ---- 5. active manifest of the new set
    QJsonArray history = current ? current->value("history").toArray() : QJsonArray();
    QStringList installedNames;
    for (const ComponentReport& c : rep.components) installedNames << c.component;
    history.append(QJsonObject{{"package_id", m.packageId}, {"package_version", m.packageVersion},
                               {"installed_at", installedAt}, {"signing_key_id", verified.keyId},
                               {"components", QJsonArray::fromStringList(installedNames)},
                               {"downgrade", options.allowDowngrade && !rep.previousPackageVersion.isEmpty() &&
                                                 parsePackageVersion(m.packageVersion) <=
                                                     parsePackageVersion(rep.previousPackageVersion)}});
    while (history.size() > kHistoryLimit) history.removeFirst();
    QJsonObject activeJson{{"format", "gamekernel-signatures"}, {"format_version", 1},
                           {"installed_at", installedAt}, {"package_id", m.packageId},
                           {"package_version", m.packageVersion}, {"publisher", m.publisher},
                           {"description", m.json.value("description")}, {"signing_key_id", verified.keyId},
                           {"components", componentsJson}, {"history", history}};
    QSaveFile mf(QDir(setDir).filePath(QStringLiteral("manifest.json")));
    if (!mf.open(QIODevice::WriteOnly) || mf.write(QJsonDocument(activeJson).toJson()) < 0 || !mf.commit())
        return failure(rep, error_code::IoError, QStringLiteral("falha ao gravar o manifesto ativo"));

    // ---- 6. swap
    QDir fs;
    if (QDir(previousDir()).exists() && !QDir(previousDir()).removeRecursively())
        return failure(rep, error_code::Busy, QStringLiteral("o conjunto anterior está em uso; tente após a varredura"));
    const bool hadActive = QDir(activeDir()).exists();
    if (hadActive && !fs.rename(activeDir(), previousDir()))
        return failure(rep, error_code::Busy, QStringLiteral("as assinaturas ativas estão em uso; tente após a varredura"));
    if (!fs.rename(setDir, activeDir())) {
        if (hadActive) fs.rename(previousDir(), activeDir());
        return failure(rep, error_code::IoError, QStringLiteral("falha ao ativar o novo conjunto; o anterior foi mantido"));
    }
    cleanup.dismiss();
    rep.activeManifest = activeJson;
    rep.ok = true;
    appendHistory(root_, QJsonObject{{"at", installedAt}, {"action", "install"}, {"package_id", m.packageId},
                                     {"package_version", m.packageVersion}, {"key_id", verified.keyId},
                                     {"components", QJsonArray::fromStringList(installedNames)}});
    return rep;
}

InstallReport Installer::rollback() {
    InstallReport rep;
    QDir().mkpath(stagingDir());
    QLockFile lock(QDir(root_).filePath(QStringLiteral(".install.lock")));
    lock.setStaleLockTime(30 * 60 * 1000);
    if (!lock.tryLock(3000))
        return failure(rep, error_code::Busy, QStringLiteral("outra instalação de assinaturas está em andamento"));
    rep.details += recoverInterrupted();
    if (!QDir(previousDir()).exists() || !QDir(activeDir()).exists())
        return failure(rep, "no_previous", QStringLiteral("não há versão anterior das assinaturas para restaurar"));

    const auto before = activeManifest();
    const QString tmp = QDir(stagingDir()).filePath(QUuid::createUuid().toString(QUuid::WithoutBraces) + "-rollback");
    QDir fs;
    if (!fs.rename(activeDir(), tmp))
        return failure(rep, error_code::Busy, QStringLiteral("as assinaturas ativas estão em uso; tente após a varredura"));
    if (!fs.rename(previousDir(), activeDir())) {
        fs.rename(tmp, activeDir());
        return failure(rep, error_code::IoError, QStringLiteral("falha ao restaurar a versão anterior"));
    }
    if (!fs.rename(tmp, previousDir())) rep.details << QStringLiteral("a versão substituída não pôde ser guardada");
    const auto after = activeManifest();
    rep.ok = true;
    rep.previousPackageVersion = before ? before->value("package_version").toString() : QString();
    rep.packageVersion = after ? after->value("package_version").toString() : QString();
    rep.packageId = after ? after->value("package_id").toString() : QString();
    if (after) rep.activeManifest = *after;
    appendHistory(root_, QJsonObject{{"at", nowIso()}, {"action", "rollback"}, {"package_version", rep.packageVersion},
                                     {"from_version", rep.previousPackageVersion}});
    return rep;
}

}  // namespace gk::updates
