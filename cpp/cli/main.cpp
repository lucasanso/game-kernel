// gk-cli — scans without the graphical interface (automation, tests, troubleshooting).
//
//   gk-cli scan <folder|file>... [--quick] [--json report.json] [--data-dir DIR] [--workers N] [--no-cache]
//   gk-cli quarantine add <file> [--expect-sha256 HASH] [--reason TEXT]
//   gk-cli quarantine list [--all] [--json out.json]
//   gk-cli quarantine restore <id> [--to PATH] [--overwrite]
//   gk-cli quarantine delete <id>
//   gk-cli quarantine verify [--json out.json]
//
// Exit codes: 0 ok / nothing suspicious · 3 threats/suspicious/PUA found · 2 error · 4 cancelled ·
//             5 damaged quarantine items found by `verify`.
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QStandardPaths>
#include <QTextStream>

#include <csignal>
#include <cstdio>

#include "gk/db.hpp"
#include "gk/error.hpp"
#include "gk/quarantine.hpp"
#include "gk/scan/scanner.hpp"
#include "gk/text.hpp"
#include "gk/version.hpp"

namespace {

gk::scan::Scanner* g_scanner = nullptr;

void on_interrupt(int) {
    if (g_scanner != nullptr) QMetaObject::invokeMethod(g_scanner, [] { g_scanner->cancel(); }, Qt::QueuedConnection);
}

QString default_data_dir() {
    const QByteArray env = qgetenv("GAMEKERNEL_DATA_DIR");
    if (!env.isEmpty()) return QString::fromLocal8Bit(env);
#ifdef Q_OS_WIN
    return QDir(QString::fromLocal8Bit(qgetenv("LOCALAPPDATA"))).filePath(QStringLiteral("GameKernel"));
#else
    return QDir(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)).filePath(QStringLiteral("game-kernel"));
#endif
}

std::filesystem::path native_path(const QString& s) { return gk::text::utf8_path(s.toStdString()); }

QJsonValue to_qjson(const nlohmann::json& j) {
    return QJsonDocument::fromJson(QByteArray::fromStdString(nlohmann::json::array({j}).dump())).array().at(0);
}

bool write_json(const QString& file, const QJsonValue& value, QTextStream& err) {
    QFile out(file);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        err << "não foi possível gravar " << file << "\n";
        return false;
    }
    out.write(value.isArray() ? QJsonDocument(value.toArray()).toJson(QJsonDocument::Indented)
                              : QJsonDocument(value.toObject()).toJson(QJsonDocument::Indented));
    return true;
}

nlohmann::json record_json(const gk::db::QuarantineRecord& r) {
    return {{"id", r.id},         {"original_path", r.original_path}, {"sha256", r.sha256},
            {"size", r.size},     {"quarantined_at", r.quarantined_at}, {"reason", r.reason},
            {"risk", r.risk},     {"classification", r.classification}, {"detection", r.detection},
            {"status", r.status}, {"stored_name", r.stored_name}};
}

struct QuarantineOptions {
    QString to, expectSha256, reason, json;
    bool overwrite = false, all = false;
};

// Synchronous: no event loop needed. Every operation goes through gk::quarantine::Manager (vault + database +
// audit log), exactly as the application does.
int run_quarantine(const QStringList& positional, const QString& data, const QuarantineOptions& opt) {
    QTextStream out(stdout);
    QTextStream err(stderr);
    const QString command = positional.value(1);
    const QString arg = positional.value(2);
    const bool needsArg = command == QStringLiteral("add") || command == QStringLiteral("restore") ||
                          command == QStringLiteral("delete");
    if (command.isEmpty() || (needsArg && arg.isEmpty())) {
        err << "uso: gk-cli quarantine add <arquivo> | list | restore <id> | delete <id> | verify\n";
        return 2;
    }
    try {
        auto vault = gk::quarantine::Vault::open(native_path(QDir(data).filePath(QStringLiteral("quarantine"))));
        for (const auto& w : vault->warnings()) err << "aviso: " << QString::fromStdString(w) << "\n";
        auto db = gk::db::Database::open(native_path(QDir(data).filePath(QStringLiteral("gamekernel.db"))));
        gk::quarantine::Manager manager(*vault, *db);

        if (command == QStringLiteral("add")) {
            gk::quarantine::Request request;
            request.file = native_path(QFileInfo(arg).absoluteFilePath());
            if (!opt.expectSha256.isEmpty()) request.expected_sha256 = opt.expectSha256.toStdString();
            request.reason = opt.reason.isEmpty() ? std::string("manual (gk-cli)") : opt.reason.toStdString();
            const auto meta = manager.quarantine(request);
            out << QString::fromStdString(meta.id) << "\n";
            if (!opt.json.isEmpty() && !write_json(opt.json, to_qjson(gk::quarantine::to_json(meta)), err)) return 2;
            return 0;
        }
        if (command == QStringLiteral("list")) {
            QJsonArray rows;
            for (const auto& r : db->list_quarantine(opt.all ? std::string() : std::string("quarantined"))) {
                out << QString::fromStdString(r.id) << "  " << QString::fromStdString(r.status) << "  "
                    << QString::fromStdString(r.original_path) << "\n";
                rows.append(to_qjson(record_json(r)));
            }
            if (!opt.json.isEmpty() && !write_json(opt.json, rows, err)) return 2;
            return 0;
        }
        if (command == QStringLiteral("restore")) {
            std::optional<std::filesystem::path> to;
            if (!opt.to.isEmpty()) to = native_path(QFileInfo(opt.to).absoluteFilePath());
            const auto where = manager.restore(arg.toStdString(), to, opt.overwrite);
            out << "restaurado em " << QString::fromStdString(gk::text::path_utf8(where)) << "\n";
            return 0;
        }
        if (command == QStringLiteral("delete")) {
            manager.erase(arg.toStdString());
            out << "item apagado definitivamente\n";
            return 0;
        }
        if (command == QStringLiteral("verify")) {
            const auto report = manager.verify();
            out << "íntegros: " << report.ok.size() << "  danificados: " << report.damaged.size()
                << "  recuperados: " << report.unknown.size() << "\n";
            QJsonArray damaged;
            for (const auto& [id, why] : report.damaged) {
                out << "  " << QString::fromStdString(id) << ": " << QString::fromStdString(why) << "\n";
                damaged.append(QJsonObject{{QStringLiteral("id"), QString::fromStdString(id)},
                                           {QStringLiteral("reason"), QString::fromStdString(why)}});
            }
            QJsonArray ok, recovered;
            for (const auto& id : report.ok) ok.append(QString::fromStdString(id));
            for (const auto& m : report.unknown) recovered.append(to_qjson(gk::quarantine::to_json(m)));
            if (!opt.json.isEmpty() &&
                !write_json(opt.json, QJsonObject{{QStringLiteral("ok"), ok}, {QStringLiteral("damaged"), damaged},
                                                  {QStringLiteral("recovered"), recovered}}, err)) {
                return 2;
            }
            return report.damaged.empty() ? 0 : 5;
        }
        err << "comando de quarentena desconhecido: " << command << "\n";
        return 2;
    } catch (const gk::Error& e) {
        err << "erro: " << QString::fromUtf8(e.what()) << "\n";
        return 2;
    } catch (const std::exception& e) {
        err << "erro interno: " << QString::fromUtf8(e.what()) << "\n";
        return 2;
    }
}

}  // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("gk-cli"));
    QCoreApplication::setApplicationVersion(QString::fromLatin1(gk::kVersion));
    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Game Kernel — análise offline sem interface gráfica"));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument(QStringLiteral("command"), QStringLiteral("scan | quarantine"));
    parser.addPositionalArgument(QStringLiteral("targets"), QStringLiteral("Pastas e/ou arquivos"), QStringLiteral("[alvos...]"));
    QCommandLineOption quick(QStringLiteral("quick"), QStringLiteral("Análise rápida"));
    QCommandLineOption json(QStringLiteral("json"), QStringLiteral("Gravar resultado JSON"), QStringLiteral("arquivo"));
    QCommandLineOption dataDir(QStringLiteral("data-dir"), QStringLiteral("Diretório de dados"), QStringLiteral("dir"));
    QCommandLineOption workers(QStringLiteral("workers"), QStringLiteral("Processos de análise"), QStringLiteral("n"), QStringLiteral("2"));
    QCommandLineOption noCache(QStringLiteral("no-cache"), QStringLiteral("Não reutilizar veredictos"));
    QCommandLineOption quiet(QStringLiteral("quiet"), QStringLiteral("Sem progresso"));
    QCommandLineOption worker(QStringLiteral("worker"), QStringLiteral("Programa de análise alternativo (diagnóstico)"),
                              QStringLiteral("arquivo"));
    QCommandLineOption fileTimeout(QStringLiteral("file-timeout"), QStringLiteral("Tempo limite por arquivo (ms)"),
                                   QStringLiteral("ms"));
    QCommandLineOption to(QStringLiteral("to"), QStringLiteral("quarantine restore: destino"), QStringLiteral("caminho"));
    QCommandLineOption overwrite(QStringLiteral("overwrite"), QStringLiteral("quarantine restore: substituir destino existente"));
    QCommandLineOption expectSha(QStringLiteral("expect-sha256"),
                                 QStringLiteral("quarantine add: recusar se o arquivo mudou desde a análise"), QStringLiteral("hash"));
    QCommandLineOption reason(QStringLiteral("reason"), QStringLiteral("quarantine add: motivo"), QStringLiteral("texto"));
    QCommandLineOption all(QStringLiteral("all"), QStringLiteral("quarantine list: incluir restaurados e apagados"));
    parser.addOptions({quick, json, dataDir, workers, noCache, quiet, worker, fileTimeout, to, overwrite, expectSha, reason, all});
    parser.process(app);
    const QStringList positional = parser.positionalArguments();
    const QString data = parser.isSet(dataDir) ? parser.value(dataDir) : default_data_dir();
    if (positional.value(0) == QStringLiteral("quarantine")) {
        QDir().mkpath(data);
        QuarantineOptions opt;
        opt.to = parser.value(to);
        opt.overwrite = parser.isSet(overwrite);
        opt.expectSha256 = parser.value(expectSha);
        opt.reason = parser.value(reason);
        opt.all = parser.isSet(all);
        opt.json = parser.value(json);
        return run_quarantine(positional, data, opt);
    }
    if (positional.size() < 2 || positional.first() != QStringLiteral("scan")) {
        parser.showHelp(2);
    }
    QDir().mkpath(data);
    gk::scan::Config config = gk::scan::Config::defaults(QCoreApplication::applicationDirPath(), data);
    config.workers = std::max(1, parser.value(workers).toInt());
    if (parser.isSet(worker)) config.workerProgram = QFileInfo(parser.value(worker)).absoluteFilePath();
    if (parser.isSet(fileTimeout)) config.fileTimeoutMs = std::max(1000, parser.value(fileTimeout).toInt());
    gk::scan::Scanner scanner(config);
    g_scanner = &scanner;
    std::signal(SIGINT, on_interrupt);

    QTextStream err(stderr);
    QJsonArray results;
    int exitCode = 0;
    QObject::connect(&scanner, &gk::scan::Scanner::progress, &app, [&](const gk::scan::Progress& p) {
        if (parser.isSet(quiet)) return;
        err << QStringLiteral("\r[%1] %2/%3 arquivos  ameaças:%4 suspeitos:%5 erros:%6   ")
                   .arg(p.phase).arg(p.filesDone).arg(p.filesTotal).arg(p.threats).arg(p.suspicious).arg(p.errors);
        err.flush();
    });
    QObject::connect(&scanner, &gk::scan::Scanner::fileResult, &app, [&](const QJsonObject& r) { results.append(r); });
    QObject::connect(&scanner, &gk::scan::Scanner::finished, &app, [&](const QJsonObject& summary) {
        if (!parser.isSet(quiet)) err << "\n";
        const QString status = summary.value(QStringLiteral("status")).toString();
        if (parser.isSet(json)) {
            QFile out(parser.value(json));
            if (out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                out.write(QJsonDocument(QJsonObject{{QStringLiteral("summary"), summary},
                                                    {QStringLiteral("results"), results}}).toJson(QJsonDocument::Indented));
            } else {
                err << "não foi possível gravar " << parser.value(json) << "\n";
            }
        }
        QTextStream outText(stdout);
        outText << "Varredura " << summary.value(QStringLiteral("scan_id")).toInteger() << ": " << status << "\n";
        for (const auto& v : results) {
            const QJsonObject r = v.toObject();
            const QString cls = r.value(QStringLiteral("classification")).toString();
            if (cls == QStringLiteral("unknown") || cls == QStringLiteral("known_legit")) continue;
            outText << QStringLiteral("  [%1] %2 — %3\n")
                           .arg(r.value(QStringLiteral("risk")).toString(), r.value(QStringLiteral("path")).toString(), cls);
        }
        const QJsonObject classes = summary.value(QStringLiteral("counts_by_classification")).toObject();
        if (status == QStringLiteral("failed")) {
            err << "erro: " << summary.value(QStringLiteral("error")).toString() << "\n";
            exitCode = 2;
        } else if (status == QStringLiteral("cancelled")) {
            exitCode = 4;
        } else if (classes.value(QStringLiteral("malware")).toInt() + classes.value(QStringLiteral("suspicious")).toInt() +
                       classes.value(QStringLiteral("pua")).toInt() > 0) {
            exitCode = 3;
        }
        QCoreApplication::exit(exitCode);
    });

    gk::scan::Request request;
    request.targets = positional.mid(1);
    for (QString& t : request.targets) t = QFileInfo(t).absoluteFilePath();
    request.deep = !parser.isSet(quick);
    request.useCache = !parser.isSet(noCache);
    request.origin = QStringLiteral("cli");
    request.label = QStringLiteral("gk-cli");
    QMetaObject::invokeMethod(&scanner, [&] { scanner.start(request); }, Qt::QueuedConnection);
    return app.exec();
}
