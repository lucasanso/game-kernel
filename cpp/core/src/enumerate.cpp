#include <algorithm>
#include <chrono>

#include "gk/error.hpp"
#include "gk/file_view.hpp"
#include "gk/scan_support.hpp"

namespace gk::scan {

namespace {

std::string utf8(const std::filesystem::path& p) {
    const auto u8 = p.u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

std::string normalized(const std::string& p) {
    std::string out = lower_ascii(p);
    std::replace(out.begin(), out.end(), '\\', '/');
    return out;
}

bool excluded(const std::string& path_norm, const std::string& ext, const EnumOptions& o) {
    for (const auto& prefix : o.excluded_paths) {
        const std::string p = normalized(prefix);
        if (!p.empty() && path_norm.rfind(p, 0) == 0) return true;
    }
    for (const auto& e : o.excluded_extensions) {
        if (lower_ascii(e) == ext) return true;
    }
    return false;
}

void consider(const std::filesystem::path& path, const std::filesystem::directory_entry* entry, const EnumOptions& o,
              EnumResult& out) {
    Candidate c;
    c.path = path;
    c.path_utf8 = utf8(path);
    std::error_code ec;
    const auto status = entry ? entry->symlink_status(ec) : std::filesystem::symlink_status(path, ec);
    if (ec || !std::filesystem::is_regular_file(status)) return;
    c.size = entry ? entry->file_size(ec) : std::filesystem::file_size(path, ec);
    const auto mtime = entry ? entry->last_write_time(ec) : std::filesystem::last_write_time(path, ec);
    c.mtime_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(mtime.time_since_epoch()).count();
    const std::string ext = extension_of(path);
    if (excluded(normalized(c.path_utf8), ext, o)) {
        c.selected = false;
        c.skip_reason = "excluído nas configurações";
        out.files.push_back(std::move(c));
        return;
    }
    try {
        c.type = identify_file(path);
    } catch (const Error& e) {
        out.errors.push_back(c.path_utf8 + ": " + e.what());
        c.selected = false;
        c.skip_reason = std::string("não foi possível ler: ") + e.what();
        out.files.push_back(std::move(c));
        return;
    }
    const auto u8name = path.filename().u8string();
    c.priority = priority(c.type, std::string_view(reinterpret_cast<const char*>(u8name.data()), u8name.size()));
    out.total_bytes += c.size;
    if (!group_enabled(c.type, o.types) && !c.type.disguised) {
        c.selected = false;
        c.skip_reason = "tipo de arquivo desativado nas configurações";
    } else if (c.type.disguised) {
        c.selected = true;   // content contradicts the extension: always analysed
    } else if (c.size > o.max_analysis_bytes && c.type.group != "executable" && c.type.group != "archive") {
        c.selected = false;
        c.skip_reason = "arquivo de dados grande: verificado apenas o cabeçalho";
    } else if (!o.deep && (c.type.group == "data" || c.type.group == "document")) {
        c.selected = false;
        c.skip_reason = "arquivo de dados: verificado apenas o cabeçalho (modo rápido)";
    } else if (!o.deep && c.type.group == "text" && c.size > 64 * 1024) {
        c.selected = false;
        c.skip_reason = "texto grande: verificado apenas o cabeçalho (modo rápido)";
    }
    out.files.push_back(std::move(c));
}

}  // namespace

EnumResult enumerate(const std::vector<std::filesystem::path>& targets, const EnumOptions& options, CancelToken* cancel,
                     const std::function<void(std::size_t)>& progress) {
    EnumResult out;
    for (const auto& target : targets) {
        std::error_code ec;
        const auto st = std::filesystem::symlink_status(target, ec);
        if (ec) {
            out.errors.push_back(utf8(target) + ": " + ec.message());
            continue;
        }
        if (std::filesystem::is_regular_file(st)) {
            consider(target, nullptr, options, out);
            continue;
        }
        if (!std::filesystem::is_directory(st)) continue;
        std::filesystem::recursive_directory_iterator it(target, std::filesystem::directory_options::skip_permission_denied, ec);
        if (ec) {
            out.errors.push_back(utf8(target) + ": " + ec.message());
            continue;
        }
        for (const auto end = std::filesystem::recursive_directory_iterator(); it != end; it.increment(ec)) {
            if (ec) {
                out.errors.push_back(ec.message());
                ec.clear();
                continue;
            }
            if (cancel != nullptr && !cancel->wait_if_paused()) return out;
            const auto& entry = *it;
            std::error_code sec;
            if (entry.is_symlink(sec)) {   // never follow links/junctions out of the selected folder
                if (entry.is_directory(sec)) it.disable_recursion_pending();
                continue;
            }
            if (entry.is_directory(sec)) {
                if (excluded(normalized(utf8(entry.path())) + "/", "", options)) it.disable_recursion_pending();
                continue;
            }
            consider(entry.path(), &entry, options, out);
            if (progress && out.files.size() % 256 == 0) progress(out.files.size());
        }
    }
    std::stable_sort(out.files.begin(), out.files.end(),
                     [](const Candidate& a, const Candidate& b) { return a.priority < b.priority; });
    return out;
}

}  // namespace gk::scan
