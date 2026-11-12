// gk-ipc v1 — C++ side of the framed JSON protocol between the Game Kernel application and
// its helper processes. Specification: docs/INTEGRATION.md. Python side: gamekernel/ipc/protocol.py.
// Both implementations must stay byte-compatible; tests/native drives the cross-language tests.
#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QString>

#include <cstdint>
#include <deque>
#include <optional>

namespace gk::ipc {

inline constexpr int kProtocolVersion = 1;
inline constexpr qint64 kDefaultMaxFrame = 8 * 1024 * 1024;
inline constexpr qint64 kMaxId = (qint64(1) << 53) - 1;   // exactly representable as a JSON double

// Stable error codes (same strings as gamekernel.ipc.protocol.ErrorCode).
namespace error_code {
inline constexpr const char* ProtocolError = "protocol_error";
inline constexpr const char* UnsupportedVersion = "unsupported_version";
inline constexpr const char* UnknownMethod = "unknown_method";
inline constexpr const char* InvalidParams = "invalid_params";
inline constexpr const char* Cancelled = "cancelled";
inline constexpr const char* Timeout = "timeout";
inline constexpr const char* ResourceLimit = "resource_limit";
inline constexpr const char* NotFound = "not_found";
inline constexpr const char* IoError = "io_error";
inline constexpr const char* Busy = "busy";
inline constexpr const char* InternalError = "internal_error";
inline constexpr const char* HelperCrashed = "helper_crashed";
inline constexpr const char* HelperUnavailable = "helper_unavailable";
}  // namespace error_code

bool isRetryable(const QString& code);

struct CallError {
    QString code;
    QString message;
    bool retryable = false;
    QJsonObject details;

    static CallError make(const char* code, const QString& message, QJsonObject details = {});
    static CallError fromJson(const QJsonObject& error);
};

// Encodes one message as a frame (uint32 LE length + UTF-8 JSON). Returns std::nullopt when the
// payload is empty or larger than maxFrame.
std::optional<QByteArray> encodeFrame(const QJsonObject& message, qint64 maxFrame = kDefaultMaxFrame);

// Validates the envelope (proto, type and per-type required fields). Returns an error text or
// std::nullopt when valid. Unknown fields are accepted (forward compatibility).
std::optional<QString> validateMessage(const QJsonObject& message);

// Incremental decoder: feed raw pipe bytes in any fragmentation, pop complete messages.
// After an error the decoder stays failed (the stream cannot be resynchronised).
class FrameDecoder {
public:
    explicit FrameDecoder(qint64 maxFrame = kDefaultMaxFrame) : maxFrame_(maxFrame) {}

    void feed(const QByteArray& bytes);
    bool hasMessage() const { return !ready_.empty(); }
    QJsonObject takeMessage();
    bool failed() const { return !error_.isEmpty(); }
    const QString& error() const { return error_; }
    qint64 bufferedBytes() const { return buffer_.size(); }

private:
    void parse();
    qint64 maxFrame_;
    QByteArray buffer_;
    std::deque<QJsonObject> ready_;
    QString error_;
};

// Message builders (host → helper).
QJsonObject makeRequest(qint64 id, const QString& method, const QJsonObject& params, int timeoutMs);
QJsonObject makeCancel(qint64 id);

}  // namespace gk::ipc
