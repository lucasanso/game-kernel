#include "gk/ipc/protocol.hpp"

#include <QJsonDocument>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QStringDecoder>
#include <QtEndian>

namespace gk::ipc {

namespace {

const QRegularExpression& methodRe() {
    static const QRegularExpression re(QStringLiteral("^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+\\z"));
    return re;
}

const QStringList& logLevels() {
    static const QStringList levels{"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"};
    return levels;
}

// A JSON number is an acceptable id only if it is an integer in [1, 2^53-1].
bool isValidId(const QJsonValue& v) {
    if (!v.isDouble()) return false;
    const double d = v.toDouble();
    if (d < 1.0 || d > double(kMaxId)) return false;
    return double(qint64(d)) == d;
}

}  // namespace

bool isRetryable(const QString& code) {
    return code == QLatin1String(error_code::Timeout) || code == QLatin1String(error_code::Busy) ||
           code == QLatin1String(error_code::HelperCrashed) || code == QLatin1String(error_code::HelperUnavailable);
}

CallError CallError::make(const char* code, const QString& message, QJsonObject details) {
    CallError e;
    e.code = QString::fromLatin1(code);
    e.message = message;
    e.retryable = isRetryable(e.code);
    e.details = std::move(details);
    return e;
}

CallError CallError::fromJson(const QJsonObject& error) {
    CallError e;
    e.code = error.value("code").toString(QString::fromLatin1(error_code::InternalError));
    e.message = error.value("message").toString();
    e.retryable = error.value("retryable").toBool(isRetryable(e.code));
    e.details = error.value("details").toObject();
    return e;
}

std::optional<QByteArray> encodeFrame(const QJsonObject& message, qint64 maxFrame) {
    const QByteArray payload = QJsonDocument(message).toJson(QJsonDocument::Compact);
    if (payload.isEmpty() || payload.size() > maxFrame) return std::nullopt;
    QByteArray frame(4, Qt::Uninitialized);
    qToLittleEndian<quint32>(quint32(payload.size()), frame.data());
    frame.append(payload);
    return frame;
}

std::optional<QString> validateMessage(const QJsonObject& m) {
    const QJsonValue proto = m.value("proto");
    if (!proto.isDouble() || proto.toDouble() != double(kProtocolVersion))
        return QStringLiteral("versão de protocolo incompatível");
    const QString type = m.value("type").toString();
    if (type == "request") {
        if (!isValidId(m.value("id"))) return QStringLiteral("id inválido");
        const QString method = m.value("method").toString();
        if (method.size() > 128 || !methodRe().match(method).hasMatch()) return QStringLiteral("método inválido");
        if (m.contains("params") && !m.value("params").isObject()) return QStringLiteral("params precisa ser objeto");
    } else if (type == "cancel") {
        if (!isValidId(m.value("id"))) return QStringLiteral("id inválido");
    } else if (type == "event") {
        if (!isValidId(m.value("id"))) return QStringLiteral("id inválido");
        if (!m.value("name").isString()) return QStringLiteral("evento sem nome");
        if (m.contains("data") && !m.value("data").isObject()) return QStringLiteral("data precisa ser objeto");
    } else if (type == "response") {
        if (!isValidId(m.value("id"))) return QStringLiteral("id inválido");
        const QJsonValue ok = m.value("ok");
        if (!ok.isBool()) return QStringLiteral("ok precisa ser booleano");
        if (ok.toBool()) {
            if (!m.contains("result")) return QStringLiteral("resposta sem result");
        } else {
            const QJsonObject err = m.value("error").toObject();
            if (!err.value("code").isString() || !err.value("message").isString())
                return QStringLiteral("erro sem code/message");
        }
    } else if (type == "log") {
        if (!logLevels().contains(m.value("level").toString()) || !m.value("message").isString())
            return QStringLiteral("log inválido");
    } else if (type == "hello") {
        if (!m.value("helper").isString() || !m.value("methods").isArray()) return QStringLiteral("hello inválido");
    } else {
        return QStringLiteral("tipo de mensagem desconhecido: %1").arg(type);
    }
    return std::nullopt;
}

void FrameDecoder::feed(const QByteArray& bytes) {
    if (failed()) return;
    buffer_.append(bytes);
    parse();
}

void FrameDecoder::parse() {
    while (!failed() && buffer_.size() >= 4) {
        const quint32 length = qFromLittleEndian<quint32>(buffer_.constData());
        if (length == 0 || qint64(length) > maxFrame_) {
            error_ = QStringLiteral("tamanho de frame inválido: %1").arg(length);
            buffer_.clear();
            return;
        }
        if (buffer_.size() < qint64(length) + 4) return;  // wait for the rest
        const QByteArray payload = buffer_.mid(4, length);
        buffer_.remove(0, qsizetype(length) + 4);

        QStringDecoder utf8(QStringDecoder::Utf8, QStringDecoder::Flag::Stateless);
        const QString text = utf8.decode(payload);
        if (utf8.hasError()) {
            error_ = QStringLiteral("frame não é UTF-8 válido");
            return;
        }
        QJsonParseError perr{};
        const QJsonDocument doc = QJsonDocument::fromJson(text.toUtf8(), &perr);
        if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
            error_ = QStringLiteral("JSON inválido: %1").arg(perr.errorString());
            return;
        }
        const QJsonObject message = doc.object();
        if (auto problem = validateMessage(message)) {
            error_ = *problem;
            return;
        }
        ready_.push_back(message);
    }
}

QJsonObject FrameDecoder::takeMessage() {
    QJsonObject m = ready_.front();
    ready_.pop_front();
    return m;
}

QJsonObject makeRequest(qint64 id, const QString& method, const QJsonObject& params, int timeoutMs) {
    QJsonObject m{{"proto", kProtocolVersion}, {"type", "request"}, {"id", double(id)}, {"method", method},
                  {"params", params}};
    if (timeoutMs > 0) m.insert("timeout_ms", timeoutMs);
    return m;
}

QJsonObject makeCancel(qint64 id) {
    return QJsonObject{{"proto", kProtocolVersion}, {"type", "cancel"}, {"id", double(id)}};
}

}  // namespace gk::ipc
