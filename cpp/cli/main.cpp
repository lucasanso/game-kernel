// gk-cli — scans without the graphical interface (automation, tests, troubleshooting).
//
//   gk-cli scan <folder|file>... [--quick] [--json report.json] [--data-dir DIR] [--workers N] [--no-cache]
//
// Exit codes: 0 nothing suspicious · 3 threats/suspicious/PUA found · 2 error · 4 cancelled.
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

#include "gk/scan/scanner.hpp"
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

}  // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("gk-cli"));
    QCoreApplication::setApplicationVersion(QString::fromLatin1(gk::kVersion));
    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Game Kernel — análise offline sem interface gráfica"));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument(QStringLiteral("command"), QStringLiteral("scan"));
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
    parser.addOptions({quick, json, dataDir, workers, noCache, quiet, worker, fileTimeout});
    parser.process(app);
    const QStringList positional = parser.positionalArguments();
    if (positional.size() < 2 || positional.first() != QStringLiteral("scan")) {
        parser.showHelp(2);
    }

    const QString data = parser.isSet(dataDir) ? parser.value(dataDir) : default_data_dir();
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
