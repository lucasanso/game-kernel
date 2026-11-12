#include "gk/updates/validators.hpp"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRegularExpression>

#if defined(GK_UPDATES_HAVE_YARA)
#include <yara.h>
#endif

namespace gk::updates {

namespace {

constexpr qint64 kMaxIocFile = qint64(256) * 1024 * 1024;
constexpr qint64 kMaxYaraFile = qint64(64) * 1024 * 1024;
constexpr int kMaxReported = 20;

QFileInfoList filesIn(const QString& dir) {
    return QDir(dir).entryInfoList(QDir::Files | QDir::NoSymLinks | QDir::Hidden, QDir::Name);
}

void report(ValidationResult& r, const QString& message) {
    if (r.messages.size() < kMaxReported) r.messages << message;
    else if (r.messages.size() == kMaxReported) r.messages << QStringLiteral("… (outros problemas omitidos)");
}

}  // namespace

bool isReservedWindowsName(const QString& fileName) {
    static const QRegularExpression re(QStringLiteral("^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\\..*)?\\z"),
                                       QRegularExpression::CaseInsensitiveOption);
    return re.match(fileName).hasMatch();
}

// ------------------------------------------------------------------------------------ IOC
ValidationResult validateIocDir(const QString& dir) {
    ValidationResult r;
    static const QRegularExpression sha(QStringLiteral("^[0-9a-f]{64}\\z"));
    static const QRegularExpression category(QStringLiteral("^[a-z_]{1,40}\\z"));
    static const QStringList severities{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"};
    QHash<QString, QString> verdicts;   // sha256 -> verdict across the whole component
    const QFileInfoList files = filesIn(dir);
    if (files.isEmpty()) {
        report(r, QStringLiteral("componente IOC sem arquivos"));
        return r;
    }
    bool failed = false;
    for (const QFileInfo& fi : files) {
        const QString name = fi.fileName();
        if (fi.suffix().toLower() != QLatin1String("json")) {
            report(r, QStringLiteral("%1: extensão não permitida").arg(name));
            failed = true;
            continue;
        }
        if (fi.size() > kMaxIocFile) {
            report(r, QStringLiteral("%1: arquivo acima de 256 MB").arg(name));
            failed = true;
            continue;
        }
        QFile f(fi.absoluteFilePath());
        if (!f.open(QIODevice::ReadOnly)) {
            report(r, QStringLiteral("%1: ilegível (%2)").arg(name, f.errorString()));
            failed = true;
            continue;
        }
        QJsonParseError perr{};
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &perr);
        if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
            report(r, QStringLiteral("%1: JSON inválido (%2)").arg(name, perr.errorString()));
            failed = true;
            continue;
        }
        const QJsonObject root = doc.object();
        if (root.value("format").toString() != QLatin1String("gamekernel-ioc")) {
            report(r, QStringLiteral("%1: formato não é gamekernel-ioc").arg(name));
            failed = true;
            continue;
        }
        if (!root.value("version").isString() || root.value("version").toString().isEmpty()) {
            report(r, QStringLiteral("%1: campo 'version' ausente").arg(name));
            failed = true;
        }
        if (!root.value("entries").isArray()) {
            report(r, QStringLiteral("%1: campo 'entries' precisa ser uma lista").arg(name));
            failed = true;
            continue;
        }
        const QJsonArray entries = root.value("entries").toArray();
        for (qsizetype i = 0; i < entries.size(); ++i) {
            const QString where = QStringLiteral("%1: entrada %2").arg(name).arg(i);
            if (!entries[i].isObject()) {
                report(r, where + QStringLiteral(" não é um objeto"));
                failed = true;
                continue;
            }
            const QJsonObject e = entries[i].toObject();
            const QString hash = e.value("sha256").toString();
            const QString verdict = e.value("verdict").toString();
            if (!e.value("sha256").isString() || !sha.match(hash).hasMatch()) {
                report(r, where + QStringLiteral(": sha256 inválido (64 caracteres hexadecimais minúsculos)"));
                failed = true;
                continue;
            }
            if (verdict != QLatin1String("bad") && verdict != QLatin1String("good")) {
                report(r, where + QStringLiteral(": verdict precisa ser 'bad' ou 'good'"));
                failed = true;
                continue;
            }
            if (e.contains("severity") && !severities.contains(e.value("severity").toString())) {
                report(r, where + QStringLiteral(": severity inválida"));
                failed = true;
            }
            if (e.contains("category") && !category.match(e.value("category").toString()).hasMatch()) {
                report(r, where + QStringLiteral(": category inválida"));
                failed = true;
            }
            for (const char* key : {"name", "source", "note"}) {
                const QJsonValue v = e.value(QLatin1String(key));
                if (!v.isUndefined() && (!v.isString() || v.toString().size() > 512)) {
                    report(r, where + QStringLiteral(": campo '%1' precisa ser texto (até 512 caracteres)").arg(key));
                    failed = true;
                }
            }
            const auto previous = verdicts.constFind(hash);
            if (previous != verdicts.constEnd() && previous.value() != verdict) {
                report(r, QStringLiteral("hash %1 aparece como 'good' e como 'bad'").arg(hash));
                failed = true;
            }
            verdicts.insert(hash, verdict);
        }
    }
    r.count = verdicts.size();
    r.ok = !failed;
    return r;
}

// ------------------------------------------------------------------------------------ ClamAV
namespace {

int minFields(const QString& ext, QChar& separator) {
    separator = ':';
    if (ext == "hdb" || ext == "hsb" || ext == "fp" || ext == "sfp") return 3;   // hash:size:name
    if (ext == "ndb") return 4;                                                   // name:type:offset:hex
    if (ext == "cdb") return 10;
    if (ext == "ldb") { separator = ';'; return 4; }                              // name;tdb;logic;sub0
    if (ext == "ign2") return 1;
    return -1;
}

void validateCvd(const QFileInfo& fi, ValidationResult& r, bool& failed) {
    QFile f(fi.absoluteFilePath());
    if (!f.open(QIODevice::ReadOnly)) {
        report(r, QStringLiteral("%1: ilegível").arg(fi.fileName()));
        failed = true;
        return;
    }
    const QByteArray header = f.read(512);
    if (header.size() != 512 || !header.startsWith("ClamAV-VDB:")) {
        report(r, QStringLiteral("%1: cabeçalho ClamAV-VDB ausente").arg(fi.fileName()));
        failed = true;
        return;
    }
    const QList<QByteArray> fields = header.trimmed().split(':');
    bool versionOk = false, sigsOk = false, levelOk = false;
    if (fields.size() >= 8) {
        fields[2].trimmed().toLongLong(&versionOk);
        const qint64 sigs = fields[3].trimmed().toLongLong(&sigsOk);
        fields[4].trimmed().toInt(&levelOk);
        if (sigsOk) r.count += sigs;
    }
    if (fields.size() < 8 || !versionOk || !sigsOk || !levelOk) {
        report(r, QStringLiteral("%1: cabeçalho ClamAV-VDB malformado").arg(fi.fileName()));
        failed = true;
        return;
    }
    if (fi.suffix().toLower() == QLatin1String("cvd")) {
        // libclamav checks the MD5 of the compressed body against the header before the RSA signature.
        QCryptographicHash md5(QCryptographicHash::Md5);
        if (!md5.addData(&f)) {
            report(r, QStringLiteral("%1: falha de leitura").arg(fi.fileName()));
            failed = true;
            return;
        }
        if (md5.result().toHex() != fields[5].trimmed().toLower()) {
            report(r, QStringLiteral("%1: MD5 do conteúdo não confere com o cabeçalho (arquivo corrompido)").arg(fi.fileName()));
            failed = true;
        }
    }
}

void validateTextDb(const QFileInfo& fi, ValidationResult& r, bool& failed) {
    QChar sep;
    const int need = minFields(fi.suffix().toLower(), sep);
    QFile f(fi.absoluteFilePath());
    if (!f.open(QIODevice::ReadOnly)) {
        report(r, QStringLiteral("%1: ilegível").arg(fi.fileName()));
        failed = true;
        return;
    }
    qint64 lineNo = 0;
    while (!f.atEnd()) {
        const QByteArray raw = f.readLine(1024 * 1024);
        ++lineNo;
        if (raw.contains('\0')) {
            report(r, QStringLiteral("%1:%2: byte nulo em base de texto").arg(fi.fileName()).arg(lineNo));
            failed = true;
            return;
        }
        const QByteArray line = raw.trimmed();
        if (line.isEmpty() || line.startsWith('#')) continue;
        if (line.count(sep.toLatin1()) + 1 < need) {
            report(r, QStringLiteral("%1:%2: linha com campos insuficientes").arg(fi.fileName()).arg(lineNo));
            failed = true;
            continue;
        }
        ++r.count;
    }
}

}  // namespace

ValidationResult validateClamavDir(const QString& dir) {
    ValidationResult r;
    const QFileInfoList files = filesIn(dir);
    if (files.isEmpty()) {
        report(r, QStringLiteral("componente ClamAV sem arquivos"));
        return r;
    }
    bool failed = false;
    for (const QFileInfo& fi : files) {
        const QString ext = fi.suffix().toLower();
        if (ext == "cvd" || ext == "cld" || ext == "cud") {
            validateCvd(fi, r, failed);
        } else {
            QChar sep;
            if (minFields(ext, sep) < 0) {
                report(r, QStringLiteral("%1: tipo de base não suportado").arg(fi.fileName()));
                failed = true;
                continue;
            }
            validateTextDb(fi, r, failed);
        }
    }
    r.ok = !failed;
    return r;
}

// ------------------------------------------------------------------------------------ YARA
#if defined(GK_UPDATES_HAVE_YARA)
namespace {

struct YaraCtx {
    ValidationResult* result;
    QString file;
    bool errors = false;
};

void yaraCallback(int level, const char* /*fileName*/, int line, const YR_RULE* /*rule*/, const char* message,
                  void* user) {
    auto* ctx = static_cast<YaraCtx*>(user);
    const QString text = QStringLiteral("%1:%2: %3").arg(ctx->file).arg(line).arg(QString::fromUtf8(message));
    if (level == YARA_ERROR_LEVEL_ERROR) {
        ctx->errors = true;
        report(*ctx->result, text);
    } else {
        report(*ctx->result, QStringLiteral("aviso: ") + text);
    }
}

const char* refuseInclude(const char* /*includeName*/, const char* /*callingFile*/, const char* /*ns*/, void* user) {
    auto* ctx = static_cast<YaraCtx*>(user);
    ctx->errors = true;
    report(*ctx->result, QStringLiteral("%1: 'include' não é permitido em pacotes de regras").arg(ctx->file));
    return nullptr;
}

void freeInclude(const char* /*ptr*/, void* /*user*/) {}

}  // namespace

bool yaraValidationAvailable() { return true; }

ValidationResult validateYaraDir(const QString& dir) {
    ValidationResult r;
    const QFileInfoList files = filesIn(dir);
    if (files.isEmpty()) {
        report(r, QStringLiteral("componente YARA sem arquivos"));
        return r;
    }
    if (yr_initialize() != ERROR_SUCCESS) {
        report(r, QStringLiteral("libyara não pôde ser inicializada"));
        return r;
    }
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        yr_finalize();
        report(r, QStringLiteral("não foi possível criar o compilador YARA"));
        return r;
    }
    YaraCtx ctx{&r, QString()};
    yr_compiler_set_callback(compiler, yaraCallback, &ctx);
    yr_compiler_set_include_callback(compiler, refuseInclude, freeInclude, &ctx);
    for (const char* name : {"filename", "filepath", "extension", "filetype"})
        yr_compiler_define_string_variable(compiler, name, "");

    for (const QFileInfo& fi : files) {
        ctx.file = fi.fileName();
        const QString ext = fi.suffix().toLower();
        if (ext != "yar" && ext != "yara") {
            report(r, QStringLiteral("%1: extensão não permitida").arg(ctx.file));
            ctx.errors = true;
            break;
        }
        QFile f(fi.absoluteFilePath());
        if (fi.size() > kMaxYaraFile || !f.open(QIODevice::ReadOnly)) {
            report(r, QStringLiteral("%1: ilegível ou acima de 64 MB").arg(ctx.file));
            ctx.errors = true;
            break;
        }
        const QByteArray source = f.readAll();
        if (source.contains('\0')) {
            report(r, QStringLiteral("%1: byte nulo no arquivo de regras").arg(ctx.file));
            ctx.errors = true;
            break;
        }
        // One namespace per file: rule names only need to be unique inside their file.
        const QByteArray ns = fi.completeBaseName().toUtf8();
        if (yr_compiler_add_string(compiler, source.constData(), ns.constData()) > 0 || ctx.errors) {
            ctx.errors = true;
            break;   // a YARA compiler cannot be reused after an error
        }
    }
    if (!ctx.errors) {
        YR_RULES* rules = nullptr;
        if (yr_compiler_get_rules(compiler, &rules) == ERROR_SUCCESS && rules) {
            const YR_RULE* rule = nullptr;
            yr_rules_foreach(rules, rule) { ++r.count; }
            yr_rules_destroy(rules);
        } else {
            ctx.errors = true;
            report(r, QStringLiteral("falha ao gerar o conjunto de regras compilado"));
        }
    }
    yr_compiler_destroy(compiler);
    yr_finalize();
    r.ok = !ctx.errors && r.count > 0;
    if (!ctx.errors && r.count == 0) report(r, QStringLiteral("nenhuma regra encontrada"));
    return r;
}
#else
bool yaraValidationAvailable() { return false; }

ValidationResult validateYaraDir(const QString&) {
    ValidationResult r;
    r.messages << QStringLiteral("validação YARA indisponível nesta compilação (libyara ausente); por segurança, "
                                 "regras não validadas não são ativadas");
    return r;
}
#endif

}  // namespace gk::updates
