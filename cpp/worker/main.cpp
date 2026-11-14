// gk-scanworker — isolated analysis process (gk-ipc v1 server, docs/INTEGRATION.md §3).
//
// The application starts N workers under a Job Object (memory limit, killed with the parent) and sends
// one file at a time. Parsers of hostile formats (PE, archives, YARA) run here, so a crash or hang only
// costs this process: the supervisor marks the file as "not analysed" and starts a new worker.
//
// Usage: gk-scanworker --rules <dir> [--rules <dir> ...] --indicators <file>
// Methods: analyze {path, deep, limits?}  ·  system.ping  ·  system.shutdown
// Events : member (one per archive member, with the request id) · log
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "gk/analysis.hpp"
#include "gk/error.hpp"
#include "gk/serialize.hpp"
#include "gk/version.hpp"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <process.h>
#define GK_GETPID _getpid
#else
#include <unistd.h>
#define GK_GETPID getpid
#endif

namespace {

using nlohmann::json;
constexpr std::uint32_t kMaxFrame = 64u << 20;

std::mutex g_out_mutex;

bool write_message(const json& message) {
    const std::string body = message.dump(-1, ' ', false, json::error_handler_t::replace);
    if (body.size() > kMaxFrame) return false;
    const auto n = static_cast<std::uint32_t>(body.size());
    const unsigned char header[4] = {static_cast<unsigned char>(n & 0xFF), static_cast<unsigned char>((n >> 8) & 0xFF),
                                     static_cast<unsigned char>((n >> 16) & 0xFF), static_cast<unsigned char>((n >> 24) & 0xFF)};
    std::lock_guard lock(g_out_mutex);
    if (std::fwrite(header, 1, 4, stdout) != 4) return false;
    if (std::fwrite(body.data(), 1, body.size(), stdout) != body.size()) return false;
    return std::fflush(stdout) == 0;
}

std::optional<json> read_message() {
    unsigned char header[4];
    if (std::fread(header, 1, 4, stdin) != 4) return std::nullopt;
    const std::uint32_t n = header[0] | (header[1] << 8) | (header[2] << 16) | (static_cast<std::uint32_t>(header[3]) << 24);
    if (n == 0 || n > kMaxFrame) return json{{"__protocol_error", "tamanho de quadro inválido"}};
    std::string body(n, '\0');
    if (std::fread(body.data(), 1, n, stdin) != n) return std::nullopt;
    try {
        return json::parse(body);
    } catch (const json::exception&) {
        return json{{"__protocol_error", "JSON inválido"}};
    }
}

json error_reply(std::int64_t id, int code, const std::string& reason, const std::string& message) {
    return json{{"v", 1}, {"id", id}, {"error", {{"code", code}, {"message", message}, {"data", {{"reason", reason}}}}}};
}

void log_event(const std::string& level, const std::string& message) {
    write_message(json{{"v", 1}, {"type", "event"}, {"name", "log"},
                       {"data", {{"level", level}, {"logger", "gk-scanworker"}, {"message", message}}}});
}

struct Request {
    std::int64_t id = 0;
    std::string method;
    json params;
};

class Worker {
public:
    Worker(gk::analysis::RuleSet rules) : rules_(std::move(rules)) {}

    int run() {
        json hello{{"v", 1},
                   {"type", "hello"},
                   {"component", "gk-scanworker"},
                   {"version", gk::kVersion},
                   {"protocol", 1},
                   {"methods", {"analyze", "system.ping", "system.shutdown"}},
                   {"pid", static_cast<std::int64_t>(GK_GETPID())},
                   {"rules", {{"detection", rules_.detection ? rules_.detection->rule_count() : 0},
                              {"indicators", rules_.indicators ? rules_.indicators->rule_count() : 0},
                              {"errors", rules_.detection_report.errors}}}};
        if (!write_message(hello)) return 2;
        std::thread reader([this] { read_loop(); });
        for (;;) {
            Request req;
            {
                std::unique_lock lock(mutex_);
                cv_.wait(lock, [this] { return !queue_.empty() || stopping_; });
                if (queue_.empty()) break;
                req = std::move(queue_.front());
                queue_.pop_front();
                current_id_ = req.id;
                token_ = std::make_shared<gk::CancelToken>();
                if (cancelled_.erase(req.id)) token_->cancel();
            }
            handle(req);
            std::lock_guard lock(mutex_);
            current_id_ = -1;
            token_.reset();
            if (shutdown_after_) break;
        }
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
        }
        // stdin EOF or shutdown: the reader exits on its own when the pipe closes.
        reader.detach();
        return 0;
    }

private:
    void read_loop() {
        for (;;) {
            auto msg = read_message();
            std::lock_guard lock(mutex_);
            if (!msg) {
                stopping_ = true;
                cv_.notify_all();
                return;
            }
            if (msg->contains("__protocol_error")) {
                log_event("ERROR", "violação de protocolo: " + (*msg)["__protocol_error"].get<std::string>());
                stopping_ = true;
                cv_.notify_all();
                return;
            }
            const std::string type = msg->value("type", "");
            if (type == "cancel") {
                const std::int64_t id = msg->value("id", static_cast<std::int64_t>(-1));
                if (id == current_id_ && token_) {
                    token_->cancel();
                } else {
                    cancelled_.insert(id);
                }
                continue;
            }
            if (!msg->contains("id") || !msg->contains("method") || msg->value("v", 0) != 1) {
                write_message(error_reply(msg->value("id", static_cast<std::int64_t>(0)), -32600, "protocol_error",
                                          "requisição inválida"));
                continue;
            }
            queue_.push_back(Request{(*msg)["id"].get<std::int64_t>(), (*msg)["method"].get<std::string>(),
                                     msg->value("params", json::object())});
            cv_.notify_all();
        }
    }

    void handle(const Request& req) {
        if (req.method == "system.ping") {
            write_message(json{{"v", 1}, {"id", req.id}, {"result", {{"pong", true}}}});
            return;
        }
        if (req.method == "system.shutdown") {
            write_message(json{{"v", 1}, {"id", req.id}, {"result", {{"stopping", true}}}});
            shutdown_after_ = true;
            return;
        }
        if (req.method != "analyze") {
            write_message(error_reply(req.id, -32601, "unknown_method", "método inexistente: " + req.method));
            return;
        }
        if (!req.params.contains("path") || !req.params["path"].is_string()) {
            write_message(error_reply(req.id, -32602, "invalid_params", "parâmetro 'path' ausente"));
            return;
        }
        gk::analysis::Options options;
        options.deep = req.params.value("deep", true);
        const json limits = req.params.value("limits", json::object());
        options.archive_limits.max_total_bytes = limits.value("max_total_bytes", options.archive_limits.max_total_bytes);
        options.archive_limits.max_member_bytes = limits.value("max_member_bytes", options.archive_limits.max_member_bytes);
        options.archive_limits.max_members = limits.value("max_members", options.archive_limits.max_members);
        options.archive_limits.max_ratio = limits.value("max_ratio", options.archive_limits.max_ratio);
        options.archive_limits.max_depth = limits.value("max_depth", options.archive_limits.max_depth);
        options.max_analysis_bytes = limits.value("max_analysis_bytes", options.max_analysis_bytes);
        try {
            const std::string path_text = req.params["path"].get<std::string>();
            const std::filesystem::path path(std::u8string(path_text.begin(), path_text.end()));
            gk::analysis::Output out = gk::analysis::analyze_file(path, rules_, options, token_.get());
            if (token_->cancelled()) {
                write_message(error_reply(req.id, 1004, "cancelled", "análise cancelada"));
                return;
            }
            for (const auto& member : out.members) {
                write_message(json{{"v", 1}, {"type", "event"}, {"name", "member"}, {"id", req.id},
                                   {"data", gk::to_json(member)}});
            }
            write_message(json{{"v", 1},
                               {"id", req.id},
                               {"result", {{"file", gk::to_json(out.result)}, {"members", out.members.size()}}}});
        } catch (const gk::Error& e) {
            const int code = static_cast<int>(e.code());
            const std::string reason = code == 1001 ? "io_error" : code == 1002 ? "resource_limit"
                                     : code == 1004 ? "cancelled" : code == 1005 ? "invalid_format" : "internal_error";
            write_message(error_reply(req.id, code, reason, e.what()));
        } catch (const std::bad_alloc&) {
            write_message(error_reply(req.id, 1002, "resource_limit", "memória insuficiente para analisar o arquivo"));
        } catch (const std::exception& e) {
            write_message(error_reply(req.id, 1099, "internal_error", e.what()));
        }
    }

    gk::analysis::RuleSet rules_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Request> queue_;
    std::set<std::int64_t> cancelled_;
    std::int64_t current_id_ = -1;
    std::shared_ptr<gk::CancelToken> token_;
    bool stopping_ = false;
    bool shutdown_after_ = false;
};

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    std::vector<std::filesystem::path> rule_dirs;
    std::filesystem::path indicators;
    for (int i = 1; i + 1 < argc; i += 2) {
        const std::string flag = argv[i];
        if (flag == "--rules") rule_dirs.emplace_back(argv[i + 1]);
        if (flag == "--indicators") indicators = argv[i + 1];
    }
    try {
        gk::analysis::RuleSet rules = gk::analysis::RuleSet::load(rule_dirs, indicators);
        return Worker(std::move(rules)).run();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "gk-scanworker: %s\n", e.what());
        return 1;
    }
}
