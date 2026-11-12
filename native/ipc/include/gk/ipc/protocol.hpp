// Helper IPC — C++ side of the envelope defined in docs/INTEGRATION.md §3 (contract owned by Agent A).
// Python side (server): gamekernel/helper/protocol.py. Optional extensions (cancel message, request
// timeout, event id, error.data.reason/retryable) are documented in contracts/helper_methods.md.
//
// This is the *reference client* written by Agent B to test the helper end to end from C++/Qt.
// The production HelperClient lives in cpp/bridge (Agent A, M13) and may adopt this code.
#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QString>

#include <cstdint>
#include <deque>
#include <optional>

namespace gk::ipc {

inline constexpr int kEnvelopeVersion = 1;     // "v" in every message
inline constexpr int kProtocolVersion = 1;     // hello.protocol
inline constexpr qint64 kDefaultMaxFrame = qint64(64) * 1024 * 1024;
inline constexpr qint64 kMaxId = (qint64(1) << 53) - 1;   // exactly representable as a JSON double

// Integer error codes of the contract.
namespace error_code {
inline constexpr int InvalidRequest = -32600;
inline constexpr int MethodNotFound = -32601;
inline constexpr int FileInaccessible = 1001;
inline constexpr int ResourceLimit = 1002;
inline constexpr int Timeout = 1003;
inline constexpr int Cancelled = 1004;
inline constexpr int InvalidFormat = 1005;
inline constexpr int Internal = 1099;
}  // namespace error_code

// Stable reason texts (error.data.reason); helper_crashed / helper_unavailable are produced locally.
namespace reason {
inline constexpr const char* ProtocolError = "protocol_error";
inline constexpr const char* UnknownMethod = "unknown_method";
inline constexpr const char* InvalidParams = "invalid_params";
inline constexpr const char* InvalidFormat = "invalid_format";
inline constexpr const char* Cancelled = "cancelled";
inline constexpr const char* Timeout = "timeout";
inline constexpr const char* ResourceLimit = "resource_limit";
inline constexpr const char* Busy = "busy";
inline constexpr const char* NotFound = "not_found";
inline constexpr const char* IoError = "io_error";
inline constexpr const char* InternalError = "internal_error";
inline constexpr const char* HelperCrashed = "helper_crashed";
inline constexpr const char* HelperUnavailable = "helper_unavailable";
}  // namespace reason

int codeForReason(const QString& reason);
QString reasonForCode(int code);
bool isRetryable(const QString& reason);

struct CallError {
    int code = error_code::Internal;
    QString reason;
    QString message;
    bool retryable = false;
    QJsonObject data;        // error.data without reason/retryable (e.g. {"field": "scan_id"})

    static CallError make(const char* reason, const QString& message, QJsonObject data = {});
    static CallError fromJson(const QJsonObject& error);
};

// One message as a frame (uint32 LE length + UTF-8 JSON). std::nullopt if empty or above maxFrame.
std::optional<QByteArray> encodeFrame(const QJsonObject& message, qint64 maxFrame = kDefaultMaxFrame);

// Envelope validation (both directions). Returns an error text, or std::nullopt when valid.
std::optional<QString> validateMessage(const QJsonObject& message);
// hello | event | cancel | request | response (call only on validated messages).
QString kindOf(const QJsonObject& message);

// Incremental decoder: feed raw pipe bytes in any fragmentation, pop complete validated messages.
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

QJsonObject makeRequest(qint64 id, const QString& method, const QJsonObject& params, int timeoutMs);
QJsonObject makeCancel(qint64 id);

}  // namespace gk::ipc
