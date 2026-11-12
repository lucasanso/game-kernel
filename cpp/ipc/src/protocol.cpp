#include "gk/ipc/protocol.hpp"

#include <QHash>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QStringDecoder>
#include <QtEndian>

#include <cmath>

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

bool isInteger(const QJsonValue& v) {
    if (!v.isDouble()) return false;
    const double d = v.toDouble();
    return std::isfinite(d) && std::floor(d) == d;
}

// A JSON number is an acceptable id only if it is an integer in [1, 2^53-1].
bool isValidId(const QJsonValue& v) {
    return isInteger(v) && v.toDouble() >= 1.0 && v.toDouble() <= double(kMaxId);
}

const QHash<QString, int>& reasonCodes() {
    static const QHash<QString, int> map{
        {reason::ProtocolError, error_code::InvalidRequest}, {reason::InvalidParams, error_code::InvalidRequest},
        {reason::UnknownMethod, error_code::MethodNotFound},  {reason::NotFound, error_code::FileInaccessible},
        {reason::IoError, error_code::FileInaccessible},      {reason::ResourceLimit, error_code::ResourceLimit},
        {reason::Busy, error_code::ResourceLimit},            {reason::Timeout, error_code::Timeout},
        {reason::Cancelled, error_code::Cancelled},           {reason::InvalidFormat, error_code::InvalidFormat},
        {reason::InternalError, error_code::Internal},        {reason::HelperCrashed, error_code::Internal},
        {reason::HelperUnavailable, error_code::Internal},
    };
    return map;
}

}  // namespace

int codeForReason(const QString& r) { return reasonCodes().value(r, error_code::Internal); }

QString reasonForCode(int code) {
    switch (code) {
        case error_code::InvalidRequest: return QString::fromLatin1(reason::ProtocolError);
        case error_code::MethodNotFound: return QString::fromLatin1(reason::UnknownMethod);
        case error_code::FileInaccessible: return QString::fromLatin1(reason::IoError);
        case error_code::ResourceLimit: return QString::fromLatin1(reason::ResourceLimit);
        case error_code::Timeout: return QString::fromLatin1(reason::Timeout);
        case error_code::Cancelled: return QString::fromLatin1(reason::Cancelled);
        case error_code::InvalidFormat: return QString::fromLatin1(reason::InvalidFormat);
        default: return QString::fromLatin1(reason::InternalError);
    }
}

bool isRetryable(const QString& r) {
    return r == QLatin1String(reason::Timeout) || r == QLatin1String(reason::Busy) ||
           r == QLatin1String(reason::HelperCrashed) || r == QLatin1String(reason::HelperUnavailable);
}

CallError CallError::make(const char* r, const QString& message, QJsonObject data) {
    CallError e;
    e.reason = QString::fromLatin1(r);
    e.code = codeForReason(e.reason);
    e.message = message;
    e.retryable = isRetryable(e.reason);
    e.data = std::move(data);
    return e;
}

CallError CallError::fromJson(const QJsonObject& error) {
    CallError e;
    e.code = isInteger(error.value("code")) ? int(error.value("code").toDouble()) : error_code::Internal;
    e.message = error.value("message").toString();
    e.data = error.value("data").toObject();
    e.reason = e.data.value("reason").toString();
    if (e.reason.isEmpty()) e.reason = reasonForCode(e.code);
    e.retryable = e.data.contains("retryable") ? e.data.value("retryable").toBool() : isRetryable(e.reason);
    e.data.remove("reason");
    e.data.remove("retryable");
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

QString kindOf(const QJsonObject& m) {
    if (m.contains("type")) return m.value("type").toString();
    return m.contains("method") ? QStringLiteral("request") : QStringLiteral("response");
}

std::optional<QString> validateMessage(const QJsonObject& m) {
    const QJsonValue v = m.value("v");
    if (!isInteger(v) || v.toDouble() != double(kEnvelopeVersion)) return QStringLiteral("versão de envelope incompatível");
    if (m.contains("type")) {
        const QString type = m.value("type").toString();
        if (type == "hello") {
            if (!m.value("component").isString() || !isInteger(m.value("protocol")))
                return QStringLiteral("hello precisa de component e protocol");
        } else if (type == "event") {
            if (!m.value("name").isString()) return QStringLiteral("evento sem nome");
            if (m.contains("data") && !m.value("data").isObject()) return QStringLiteral("data precisa ser objeto");
            if (m.contains("id") && !isValidId(m.value("id"))) return QStringLiteral("id inválido");
            if (m.value("name").toString() == "log") {
                const QJsonObject d = m.value("data").toObject();
                if (!logLevels().contains(d.value("level").toString()) || !d.value("message").isString())
                    return QStringLiteral("evento log inválido");
            }
        } else if (type == "cancel") {
            if (!isValidId(m.value("id"))) return QStringLiteral("id inválido");
        } else {
            return QStringLiteral("tipo de mensagem desconhecido: %1").arg(type);
        }
        return std::nullopt;
    }
    if (!isValidId(m.value("id"))) return QStringLiteral("id inválido");
    if (m.contains("method")) {
        const QString method = m.value("method").toString();
        if (!m.value("method").isString() || method.size() > 128 || !methodRe().match(method).hasMatch())
            return QStringLiteral("método inválido");
        if (m.contains("params") && !m.value("params").isObject()) return QStringLiteral("params precisa ser objeto");
        if (m.contains("timeout_ms") && (!isInteger(m.value("timeout_ms")) || m.value("timeout_ms").toDouble() <= 0))
            return QStringLiteral("timeout_ms inválido");
        return std::nullopt;
    }
    const bool hasResult = m.contains("result");
    const bool hasError = m.contains("error");
    if (hasResult == hasError) return QStringLiteral("resposta precisa de result ou error");
    if (hasError) {
        const QJsonObject err = m.value("error").toObject();
        if (!m.value("error").isObject() || !isInteger(err.value("code")) || !err.value("message").isString())
            return QStringLiteral("erro precisa de code (inteiro) e message");
        if (err.contains("data") && !err.value("data").isObject()) return QStringLiteral("error.data precisa ser objeto");
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
    QJsonObject m{{"v", kEnvelopeVersion}, {"id", double(id)}, {"method", method}, {"params", params}};
    if (timeoutMs > 0) m.insert("timeout_ms", timeoutMs);
    return m;
}

QJsonObject makeCancel(qint64 id) {
    return QJsonObject{{"v", kEnvelopeVersion}, {"type", "cancel"}, {"id", double(id)}};
}

}  // namespace gk::ipc
