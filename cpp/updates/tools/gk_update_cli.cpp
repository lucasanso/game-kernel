// gk-update — command-line front end of the C++ offline update installer.
// Used by the automated tests (pytest drives it), by administrators and as the reference for
// how the application calls gk::updates. Every command prints one JSON object on stdout.
//
//   gk-update verify   <package> --keys <dir> [--keys <dir>...] [--app-version X.Y.Z]
//   gk-update install  <package> --root <signatures-dir> --keys <dir>... [--allow-downgrade]
//   gk-update rollback --root <signatures-dir>
//   gk-update status   --root <signatures-dir>
//   gk-update validate --component ioc|clamav|yara --dir <dir>
//
// Exit codes: 0 success, 1 rejected/failed (see "error.code"), 2 usage error.
#include "gk/updates/installer.hpp"
#include "gk/updates/package.hpp"
#include "gk/updates/validators.hpp"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTextStream>

#include <cstdio>

using namespace gk::updates;

namespace {

int printJson(const QJsonObject& o, int code) {
    const QByteArray out = QJsonDocument(o).toJson(QJsonDocument::Compact);
    std::fwrite(out.constData(), 1, size_t(out.size()), stdout);
    std::fputc('\n', stdout);
    return code;
}

int usage(const QString& message) {
    return printJson(QJsonObject{{"ok", false}, {"error", QJsonObject{{"code", "usage"}, {"message", message}}}}, 2);
}

QJsonObject verifyJson(const VerifyResult& r) {
    QJsonObject o{{"ok", r.ok}};
    if (r.ok) {
        o.insert("key_id", r.keyId);
        o.insert("manifest", r.manifest.json);
    } else {
        o.insert("error", QJsonObject{{"code", r.error.code}, {"message", r.error.message}});
    }
    return o;
}

}  // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("gk-update");
    QCommandLineParser parser;
    parser.addPositionalArgument("command", "verify | install | rollback | status | validate");
    parser.addPositionalArgument("package", "pacote .gkpkg", "[package]");
    QCommandLineOption keys("keys", "pasta com chaves públicas confiáveis (*.pub)", "dir");
    QCommandLineOption root("root", "pasta de assinaturas (<dados>/signatures)", "dir");
    QCommandLineOption appVersion("app-version", "versão do aplicativo", "version", "1.0.0");
    QCommandLineOption allowDowngrade("allow-downgrade", "permite instalar versão mais antiga (confirmação explícita)");
    QCommandLineOption component("component", "ioc | clamav | yara", "name");
    QCommandLineOption dir("dir", "pasta a validar", "dir");
    parser.addOptions({keys, root, appVersion, allowDowngrade, component, dir});
    parser.addHelpOption();
    parser.process(app);

    const QStringList args = parser.positionalArguments();
    if (args.isEmpty()) return usage("comando ausente");
    const QString cmd = args.first();
    QStringList keyProblems;
    const std::vector<TrustedKey> trusted = loadTrustedKeys(parser.values(keys), &keyProblems);

    if (cmd == "verify") {
        if (args.size() != 2) return usage("uso: gk-update verify <pacote> --keys <pasta>");
        const VerifyResult r = verifyPackage(args[1], trusted, parser.value(appVersion));
        QJsonObject o = verifyJson(r);
        o.insert("key_problems", QJsonArray::fromStringList(keyProblems));
        return printJson(o, r.ok ? 0 : 1);
    }
    if (cmd == "install" || cmd == "rollback" || cmd == "status") {
        if (!parser.isSet(root)) return usage("--root é obrigatório");
        Installer installer(parser.value(root), trusted, parser.value(appVersion));
        if (cmd == "status") {
            const auto manifest = installer.activeManifest();
            return printJson(QJsonObject{{"ok", true}, {"active", manifest ? QJsonValue(*manifest) : QJsonValue()},
                                    {"yara_validation", yaraValidationAvailable()}}, 0);
        }
        InstallReport rep;
        if (cmd == "rollback") {
            rep = installer.rollback();
        } else {
            if (args.size() != 2) return usage("uso: gk-update install <pacote> --root <pasta> --keys <pasta>");
            InstallOptions options;
            options.allowDowngrade = parser.isSet(allowDowngrade);
            rep = installer.install(args[1], options);
        }
        return printJson(rep.toJson(), rep.ok ? 0 : 1);
    }
    if (cmd == "validate") {
        const QString comp = parser.value(component);
        ValidationResult vr;
        if (comp == "ioc") vr = validateIocDir(parser.value(dir));
        else if (comp == "clamav") vr = validateClamavDir(parser.value(dir));
        else if (comp == "yara") vr = validateYaraDir(parser.value(dir));
        else return usage("--component precisa ser ioc, clamav ou yara");
        return printJson(QJsonObject{{"ok", vr.ok}, {"count", double(vr.count)},
                                {"messages", QJsonArray::fromStringList(vr.messages)}}, vr.ok ? 0 : 1);
    }
    return usage(QStringLiteral("comando desconhecido: %1").arg(cmd));
}
