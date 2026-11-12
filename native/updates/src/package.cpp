#include "gk/updates/package.hpp"
#include "gk/updates/validators.hpp"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QSet>
#include <QStringDecoder>
#include <QtEndian>

#include <sodium.h>

#include <cmath>
#include <cstring>

namespace gk::updates {

namespace {

constexpr qint64 kChunk = 1024 * 1024;
const unsigned char kEd25519SpkiPrefix[12] = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};

const QRegularExpression& pathRe() {
    static const QRegularExpression re(QStringLiteral("^(clamav|yara|ioc)/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\z"));
    return re;
}
const QRegularExpression& packageVersionRe() {
    static const QRegularExpression re(QStringLiteral("^\\d{4}\\.\\d{1,2}\\.\\d{1,2}(\\.\\d{1,4})?\\z"));
    return re;
}
const QRegularExpression& appVersionRe() {
    static const QRegularExpression re(QStringLiteral("^\\d{1,4}\\.\\d{1,4}\\.\\d{1,4}\\z"));
    return re;
}
const QRegularExpression& shaRe() {
    static const QRegularExpression re(QStringLiteral("^[0-9a-f]{64}\\z"));
    return re;
}
const QRegularExpression& keyIdRe() {
    static const QRegularExpression re(QStringLiteral("^[0-9a-f]{16}\\z"));
    return re;
}

const QStringList kComponents{"clamav", "yara", "ioc"};

bool extensionAllowed(const QString& component, const QString& name) {
    static const QHash<QString, QStringList> allowed{
        {"clamav", {".cvd", ".cld", ".cud", ".hdb", ".hsb", ".ndb", ".ldb", ".cdb", ".ign2", ".fp", ".sfp"}},
        {"yara", {".yar", ".yara"}},
        {"ioc", {".json"}},
    };
    const qsizetype dot = name.lastIndexOf('.');
    if (dot <= 0) return false;   // the first character is alphanumeric (regex), so dot > 0 for any extension
    return allowed.value(component).contains(name.mid(dot).toLower());
}

// JSON integer rule shared with Python's _as_int: integral number, |v| <= 2^53, not a bool.
std::optional<qint64> asInt(const QJsonValue& v) {
    if (!v.isDouble()) return std::nullopt;
    const double d = v.toDouble();
    if (!std::isfinite(d) || std::floor(d) != d || std::fabs(d) > 9007199254740992.0) return std::nullopt;
    return qint64(d);
}

bool nonEmptyString(const QJsonObject& o, const char* key) {
    const QJsonValue v = o.value(QLatin1String(key));
    return v.isString() && !v.toString().isEmpty();
}

VerifyResult fail(const char* code, const QString& message) {
    VerifyResult r;
    r.ok = false;
    r.error = {QString::fromLatin1(code), message};
    return r;
}

bool sodiumReady() {
    static const bool ok = sodium_init() >= 0;
    return ok;
}

}  // namespace

// ------------------------------------------------------------------------------------ keys
QString keyIdOf(const std::array<unsigned char, 32>& raw) {
    const QByteArray digest = QCryptographicHash::hash(
        QByteArray(reinterpret_cast<const char*>(raw.data()), qsizetype(raw.size())), QCryptographicHash::Sha256);
    return QString::fromLatin1(digest.toHex().left(16));
}

std::optional<TrustedKey> parsePublicKeyPem(const QByteArray& pem, const QString& source) {
    const QByteArray begin("-----BEGIN PUBLIC KEY-----");
    const QByteArray end("-----END PUBLIC KEY-----");
    const qsizetype b = pem.indexOf(begin);
    const qsizetype e = pem.indexOf(end);
    if (b < 0 || e < 0 || e <= b) return std::nullopt;
    QByteArray body = pem.mid(b + begin.size(), e - b - begin.size());
    body = body.simplified().replace(' ', QByteArray());
    const auto decoded = QByteArray::fromBase64Encoding(body, QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded) return std::nullopt;
    const QByteArray der = decoded.decoded;
    if (der.size() != 44 || std::memcmp(der.constData(), kEd25519SpkiPrefix, sizeof(kEd25519SpkiPrefix)) != 0)
        return std::nullopt;
    TrustedKey key;
    std::memcpy(key.raw.data(), der.constData() + 12, 32);
    key.id = keyIdOf(key.raw);
    key.source = source;
    return key;
}

std::vector<TrustedKey> loadTrustedKeys(const QStringList& directories, QStringList* problems) {
    std::vector<TrustedKey> keys;
    QSet<QString> seen;
    for (const QString& dirPath : directories) {
        const QDir dir(dirPath);
        if (!dir.exists()) continue;
        const QFileInfoList entries = dir.entryInfoList({"*.pub"}, QDir::Files | QDir::NoSymLinks, QDir::Name);
        for (const QFileInfo& fi : entries) {
            QFile f(fi.absoluteFilePath());
            if (fi.size() > 4096 || !f.open(QIODevice::ReadOnly)) {
                if (problems) problems->append(QStringLiteral("chave ilegível: %1").arg(fi.absoluteFilePath()));
                continue;
            }
            auto key = parsePublicKeyPem(f.readAll(), fi.absoluteFilePath());
            if (!key) {
                if (problems) problems->append(QStringLiteral("não é uma chave Ed25519 válida: %1").arg(fi.absoluteFilePath()));
                continue;
            }
            if (seen.contains(key->id)) continue;
            seen.insert(key->id);
            keys.push_back(*key);
        }
    }
    return keys;
}

// ------------------------------------------------------------------------------------ versions
std::optional<std::array<int, 4>> parsePackageVersion(const QString& v) {
    if (!packageVersionRe().match(v).hasMatch()) return std::nullopt;
    std::array<int, 4> out{0, 0, 0, 0};
    const QStringList parts = v.split('.');
    for (int i = 0; i < parts.size(); ++i) out[size_t(i)] = parts[i].toInt();
    return out;
}

std::optional<std::array<int, 3>> parseAppVersion(const QString& v) {
    if (!appVersionRe().match(v).hasMatch()) return std::nullopt;
    const QStringList parts = v.split('.');
    return std::array<int, 3>{parts[0].toInt(), parts[1].toInt(), parts[2].toInt()};
}

// ------------------------------------------------------------------------------------ manifest
QStringList validateManifest(const QJsonObject& m, Manifest* parsed) {
    QStringList errors;
    static const char* required[] = {"format", "format_version", "package_id", "package_version", "created_at",
                                     "publisher", "min_app_version", "components", "files", "signing_key_id"};
    for (const char* key : required)
        if (!m.contains(QLatin1String(key))) errors << QStringLiteral("campo obrigatório ausente: %1").arg(key);
    if (!errors.isEmpty()) return errors;

    if (m.value("format").toString() != QLatin1String("gamekernel-update") ||
        asInt(m.value("format_version")) != std::optional<qint64>(kFormatVersion))
        errors << QStringLiteral("formato de pacote não suportado");
    for (const char* key : {"package_id", "created_at", "publisher", "min_app_version", "package_version",
                            "signing_key_id"})
        if (!nonEmptyString(m, key)) errors << QStringLiteral("campo '%1' precisa ser texto não vazio").arg(key);
    if (!errors.isEmpty()) return errors;

    if (!parsePackageVersion(m.value("package_version").toString()))
        errors << QStringLiteral("versão de pacote inválida");
    if (!parseAppVersion(m.value("min_app_version").toString()))
        errors << QStringLiteral("versão de aplicativo inválida");
    if (!keyIdRe().match(m.value("signing_key_id").toString()).hasMatch())
        errors << QStringLiteral("signing_key_id inválido");

    QJsonObject components;
    if (!m.value("components").isObject() || m.value("components").toObject().isEmpty()) {
        errors << QStringLiteral("o pacote precisa declarar ao menos um componente");
    } else {
        components = m.value("components").toObject();
    }
    for (auto it = components.begin(); it != components.end(); ++it) {
        if (!kComponents.contains(it.key())) {
            errors << QStringLiteral("componente desconhecido: %1").arg(it.key());
        } else {
            const QJsonObject meta = it.value().toObject();
            if (!it.value().isObject() || !meta.value("version").isString() || meta.value("version").toString().isEmpty())
                errors << QStringLiteral("componente %1 sem versão").arg(it.key());
        }
    }

    const QJsonValue filesValue = m.value("files");
    if (!filesValue.isArray() || filesValue.toArray().isEmpty()) {
        errors << QStringLiteral("o pacote não contém arquivos");
        return errors;
    }
    const QJsonArray files = filesValue.toArray();
    if (files.size() > kMaxFiles) errors << QStringLiteral("arquivos demais (%1 > %2)").arg(files.size()).arg(kMaxFiles);

    QSet<QString> seen;
    QSet<QString> used;
    qint64 total = 0;
    std::vector<FileEntry> entries;
    for (const QJsonValue& v : files) {
        if (!v.isObject()) {
            errors << QStringLiteral("entrada de arquivo inválida");
            continue;
        }
        const QJsonObject o = v.toObject();
        const QJsonValue pathValue = o.value("path");
        const QString path = pathValue.toString();
        if (!pathValue.isString() || !pathRe().match(path).hasMatch() || path.contains(QLatin1String(".."))) {
            errors << QStringLiteral("caminho não permitido: %1").arg(path);
            continue;
        }
        FileEntry fe;
        fe.path = path;
        fe.component = path.section('/', 0, 0);
        fe.name = path.section('/', 1);
        if (!extensionAllowed(fe.component, fe.name))
            errors << QStringLiteral("extensão não permitida em %1: %2").arg(fe.component, path);
        if (isReservedWindowsName(fe.name)) errors << QStringLiteral("nome reservado do Windows: %1").arg(path);
        if (seen.contains(path.toLower())) errors << QStringLiteral("arquivo duplicado: %1").arg(path);
        seen.insert(path.toLower());
        const auto size = asInt(o.value("size"));
        if (!size || *size < 0 || *size > kMaxFileSize) {
            errors << QStringLiteral("tamanho inválido para %1").arg(path);
        } else {
            fe.size = *size;
            total += *size;
        }
        const QString sha = o.value("sha256").toString();
        if (!o.value("sha256").isString() || !shaRe().match(sha).hasMatch())
            errors << QStringLiteral("sha256 inválido para %1").arg(path);
        fe.sha256Hex = sha.toLatin1();
        if (!components.contains(fe.component))
            errors << QStringLiteral("arquivo %1 pertence a um componente não declarado").arg(path);
        used.insert(fe.component);
        entries.push_back(fe);
    }
    for (auto it = components.begin(); it != components.end(); ++it)
        if (!used.contains(it.key())) errors << QStringLiteral("componente %1 declarado sem arquivos").arg(it.key());
    if (total > kMaxTotal) errors << QStringLiteral("tamanho total do pacote acima do limite");

    if (errors.isEmpty() && parsed) {
        parsed->json = m;
        parsed->packageId = m.value("package_id").toString();
        parsed->packageVersion = m.value("package_version").toString();
        parsed->publisher = m.value("publisher").toString();
        parsed->minAppVersion = m.value("min_app_version").toString();
        parsed->signingKeyId = m.value("signing_key_id").toString();
        parsed->components = components;
        parsed->files = std::move(entries);
    }
    return errors;
}

// ------------------------------------------------------------------------------------ verification
VerifyResult verifyPackage(const QString& packagePath, const std::vector<TrustedKey>& keys, const QString& appVersion,
                           const PayloadSink& sink) {
    if (!sodiumReady()) return fail(error_code::IoError, QStringLiteral("libsodium não pôde ser inicializada"));
    QFile f(packagePath);
    if (!f.open(QIODevice::ReadOnly)) return fail(error_code::IoError, QStringLiteral("não foi possível abrir: %1").arg(f.errorString()));

    auto readExact = [&](qint64 n, QByteArray& out) -> bool {
        out = f.read(n);
        return out.size() == n;
    };

    QByteArray magic;
    if (!readExact(8, magic)) return fail(error_code::Truncated, QStringLiteral("pacote truncado (assinatura do formato)"));
    if (std::memcmp(magic.constData(), kMagic, 6) != 0)
        return fail(error_code::NotAPackage, QStringLiteral("não é um pacote do Game Kernel (.gkpkg)"));
    if (std::memcmp(magic.constData(), kMagic, 8) != 0)
        return fail(error_code::UnsupportedFormat, QStringLiteral("versão de formato não suportada: %1").arg(int(uchar(magic[6]))));

    QByteArray lenBytes;
    if (!readExact(4, lenBytes)) return fail(error_code::Truncated, QStringLiteral("pacote truncado (tamanho do manifesto)"));
    const quint32 manifestLen = qFromLittleEndian<quint32>(lenBytes.constData());
    if (manifestLen < 1 || qint64(manifestLen) > kMaxManifest)
        return fail(error_code::InvalidHeader, QStringLiteral("tamanho de manifesto inválido"));
    QByteArray manifestBytes;
    if (!readExact(manifestLen, manifestBytes)) return fail(error_code::Truncated, QStringLiteral("pacote truncado (manifesto)"));
    QByteArray sigLenBytes;
    if (!readExact(4, sigLenBytes)) return fail(error_code::Truncated, QStringLiteral("pacote truncado (tamanho da assinatura)"));
    if (qFromLittleEndian<quint32>(sigLenBytes.constData()) != kSigLen)
        return fail(error_code::InvalidHeader, QStringLiteral("tamanho de assinatura inválido"));
    QByteArray signature;
    if (!readExact(kSigLen, signature)) return fail(error_code::Truncated, QStringLiteral("pacote truncado (assinatura)"));

    if (keys.empty()) return fail(error_code::NoTrustedKeys, QStringLiteral("nenhuma chave pública confiável está instalada"));
    const QByteArray signedPrefix = magic + lenBytes + manifestBytes;
    const TrustedKey* signer = nullptr;
    for (const TrustedKey& key : keys) {
        if (crypto_sign_verify_detached(reinterpret_cast<const unsigned char*>(signature.constData()),
                                        reinterpret_cast<const unsigned char*>(signedPrefix.constData()),
                                        quint64(signedPrefix.size()), key.raw.data()) == 0) {
            signer = &key;
            break;
        }
    }
    if (!signer) return fail(error_code::BadSignature, QStringLiteral("assinatura inválida ou feita por uma chave não confiável"));

    // From here on the manifest bytes are authentic (but still validated: the publisher may err).
    QStringDecoder utf8(QStringDecoder::Utf8, QStringDecoder::Flag::Stateless);
    const QString text = utf8.decode(manifestBytes);
    if (utf8.hasError()) return fail(error_code::InvalidManifest, QStringLiteral("manifesto ilegível: UTF-8 inválido"));
    QJsonParseError perr{};
    const QJsonDocument doc = QJsonDocument::fromJson(text.toUtf8(), &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject())
        return fail(error_code::InvalidManifest, QStringLiteral("manifesto ilegível: %1").arg(perr.errorString()));

    VerifyResult result;
    const QStringList problems = validateManifest(doc.object(), &result.manifest);
    if (!problems.isEmpty()) return fail(error_code::InvalidManifest, problems.join(QStringLiteral("; ")));
    const auto minimum = parseAppVersion(result.manifest.minAppVersion);
    const auto current = parseAppVersion(appVersion);
    if (!current) return fail(error_code::IoError, QStringLiteral("versão do aplicativo inválida: %1").arg(appVersion));
    if (*minimum > *current)
        return fail(error_code::IncompatibleApp, QStringLiteral("pacote exige o Game Kernel %1 ou mais novo (instalado: %2)")
                                                     .arg(result.manifest.minAppVersion, appVersion));

    QByteArray buffer;
    for (const FileEntry& entry : result.manifest.files) {
        QCryptographicHash hash(QCryptographicHash::Sha256);
        qint64 remaining = entry.size;
        if (remaining == 0 && sink && !sink(entry, nullptr, 0, true))
            return fail(error_code::IoError, QStringLiteral("falha ao gravar %1").arg(entry.path));
        while (remaining > 0) {
            buffer = f.read(qMin(kChunk, remaining));
            if (buffer.isEmpty()) return fail(error_code::Truncated, QStringLiteral("pacote truncado em %1").arg(entry.path));
            hash.addData(buffer);
            remaining -= buffer.size();
            if (sink && !sink(entry, buffer.constData(), buffer.size(), remaining == 0))
                return fail(error_code::IoError, QStringLiteral("falha ao gravar %1").arg(entry.path));
        }
        if (hash.result().toHex() != entry.sha256Hex)
            return fail(error_code::HashMismatch, QStringLiteral("conteúdo adulterado: hash de %1 não confere").arg(entry.path));
    }
    if (!f.read(1).isEmpty()) return fail(error_code::TrailingData, QStringLiteral("dados extras após o último arquivo"));

    result.ok = true;
    result.keyId = signer->id;
    return result;
}

}  // namespace gk::updates
