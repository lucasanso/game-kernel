// Error type shared by the core, the worker IPC and the Python bindings.
// Codes match docs/INTEGRATION.md §3.
#pragma once

#include <stdexcept>
#include <string>

namespace gk {

enum class ErrorCode : int {
    InvalidRequest = -32600,
    MethodNotFound = -32601,
    FileAccess = 1001,
    ResourceLimit = 1002,
    Timeout = 1003,
    Cancelled = 1004,
    InvalidFormat = 1005,
    Internal = 1099,
};

class Error : public std::runtime_error {
public:
    Error(ErrorCode code, const std::string& message) : std::runtime_error(message), code_(code) {}
    [[nodiscard]] ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

}  // namespace gk
