#include "gk/yara_engine.hpp"

// libyara headers use zero-size arrays (a C extension); keep our strict warnings for our own code only.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4200 4201)
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <yara.h>
#if defined(_MSC_VER)
#pragma warning(pop)
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <algorithm>
#include <cstdio>
#include <mutex>

#include "gk/error.hpp"
#include "gk/file_view.hpp"
#include "gk/filetype.hpp"
#include "gk/text.hpp"

namespace gk::yara {

namespace {

constexpr std::uint32_t kMaxMatchData = 96;

void ensure_initialized() {
    static std::once_flag once;
    std::call_once(once, [] {
        if (yr_initialize() != ERROR_SUCCESS) throw Error(ErrorCode::Internal, "falha ao inicializar o YARA");
        std::uint32_t max_data = kMaxMatchData;
        yr_set_configuration(YR_CONFIG_MAX_MATCH_DATA, &max_data);
        // libyara is finalized by the OS at process exit; calling yr_finalize from a static
        // destructor would race with other static destructors that still hold rules.
    });
}

std::string path_utf8(const std::filesystem::path& p) {
    const auto u8 = p.u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

struct CompilerMessages {
    std::vector<std::string>* errors;
    std::vector<std::string>* warnings;
    std::string current_file;
};

void compiler_callback(int level, const char* file_name, int line, const YR_RULE* /*rule*/, const char* message,
                       void* user_data) {
    auto* msgs = static_cast<CompilerMessages*>(user_data);
    std::string text = (file_name != nullptr && *file_name != '\0') ? std::string(file_name) : msgs->current_file;
    text += ":" + std::to_string(line) + ": " + (message != nullptr ? message : "?");
    (level == YARA_ERROR_LEVEL_ERROR ? msgs->errors : msgs->warnings)->push_back(std::move(text));
}

const char* deny_include(const char* /*include_name*/, const char* /*calling_file*/, const char* /*ns*/,
                         void* /*user_data*/) {
    return nullptr;  // `include` is not allowed: rule packages must be self-contained
}

class Compiler {
public:
    explicit Compiler(CompilerMessages& msgs) {
        ensure_initialized();
        if (yr_compiler_create(&c_) != ERROR_SUCCESS) throw Error(ErrorCode::Internal, "falha ao criar compilador YARA");
        yr_compiler_set_callback(c_, compiler_callback, &msgs);
        yr_compiler_set_include_callback(c_, deny_include, nullptr, nullptr);
        for (const char* name : {"filename", "filepath", "extension", "filetype"}) {
            yr_compiler_define_string_variable(c_, name, "");
        }
    }
    ~Compiler() {
        if (c_ != nullptr) yr_compiler_destroy(c_);
    }
    Compiler(const Compiler&) = delete;
    Compiler& operator=(const Compiler&) = delete;
    YR_COMPILER* get() const { return c_; }

private:
    YR_COMPILER* c_ = nullptr;
};

std::string read_text(const std::filesystem::path& path) {
    constexpr std::uint64_t kMaxRuleFile = 64ull << 20;
    ReadOnlyFile file = ReadOnlyFile::open(path);
    if (file.size() > kMaxRuleFile) throw Error(ErrorCode::ResourceLimit, "arquivo de regras grande demais: " + path_utf8(path));
    std::string out(static_cast<std::size_t>(file.size()), '\0');
    std::size_t done = 0;
    while (done < out.size()) {
        const std::size_t got = file.read(reinterpret_cast<std::uint8_t*>(out.data()) + done, out.size() - done);
        if (got == 0) break;
        done += got;
    }
    out.resize(done);
    return out;
}

std::map<std::string, std::string> meta_of(const YR_RULE* rule) {
    std::map<std::string, std::string> out;
    const YR_META* meta = nullptr;
    yr_rule_metas_foreach(rule, meta) {
        if (meta->type == META_TYPE_STRING) {
            out[meta->identifier] = meta->string != nullptr ? meta->string : "";
        } else if (meta->type == META_TYPE_BOOLEAN) {
            out[meta->identifier] = meta->integer != 0 ? "true" : "false";
        } else {
            out[meta->identifier] = std::to_string(meta->integer);
        }
    }
    return out;
}

std::size_t count_rules(YR_RULES* rules) {
    std::size_t n = 0;
    YR_RULE* rule = nullptr;
    yr_rules_foreach(rules, rule) { ++n; }
    return n;
}

std::string excerpt_of(const std::uint8_t* data, std::size_t size) {
    // Same rendering as gamekernel.core.models.printable_excerpt (UTF-16 heuristic as in the Python engine).
    std::u32string cps;
    const bool wide = size >= 4 && data[1] == 0 && data[3] == 0;
    if (wide) {
        const std::string utf8 = text::utf16le_to_utf8(ByteView(data, size), size / 2);
        // decode the UTF-8 we just produced back into code points
        for (std::size_t i = 0; i < utf8.size();) {
            const auto c = static_cast<std::uint8_t>(utf8[i]);
            std::uint32_t cp = c;
            std::size_t len = 1;
            if (c >= 0xF0) {
                cp = c & 0x07;
                len = 4;
            } else if (c >= 0xE0) {
                cp = c & 0x0F;
                len = 3;
            } else if (c >= 0xC0) {
                cp = c & 0x1F;
                len = 2;
            }
            for (std::size_t k = 1; k < len && i + k < utf8.size(); ++k) cp = (cp << 6) | (utf8[i + k] & 0x3F);
            cps.push_back(cp);
            i += len;
        }
    } else {
        for (std::size_t i = 0; i < size; ++i) cps.push_back(data[i]);
    }
    constexpr std::size_t kLimit = 96;
    std::string out;
    for (std::size_t i = 0; i < cps.size() && i < kLimit; ++i) {
        const std::uint32_t cp = cps[i];
        if (cp == '\r' || cp == '\n' || cp == '\t') {
            out.push_back(' ');
        } else if ((cp >= 32 && cp < 127) || cp >= 160) {
            text::append_utf8(out, cp);
        } else {
            out.push_back('.');
        }
    }
    if (cps.size() > kLimit) out += "\xE2\x80\xA6";  // …
    return out;
}

struct ScanState {
    const ScanOptions* options;
    ScanResult* result;
};

int scan_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    auto* state = static_cast<ScanState*>(user_data);
    if (state->options->cancel != nullptr && state->options->cancel->cancelled()) {
        state->result->cancelled = true;
        return CALLBACK_ABORT;
    }
    if (message == CALLBACK_MSG_TOO_MANY_MATCHES) {
        state->result->truncated = true;
        return CALLBACK_CONTINUE;
    }
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;
    if (state->result->matches.size() >= state->options->max_rules) {
        state->result->truncated = true;
        return CALLBACK_CONTINUE;
    }
    const auto* rule = static_cast<YR_RULE*>(message_data);
    RuleMatch m;
    m.rule = rule->identifier;
    m.ns = rule->ns != nullptr && rule->ns->name != nullptr ? rule->ns->name : "";
    const char* tag = nullptr;
    yr_rule_tags_foreach(rule, tag) { m.tags.emplace_back(tag); }
    m.meta = meta_of(rule);
    const YR_STRING* string = nullptr;
    yr_rule_strings_foreach(rule, string) {
        std::size_t taken = 0;
        const YR_MATCH* match = nullptr;
        yr_string_matches_foreach(context, string, match) {
            if (taken >= state->options->max_instances_per_string) {
                state->result->truncated = true;
                break;
            }
            if (m.strings.size() >= state->options->max_strings_per_rule) {
                state->result->truncated = true;
                break;
            }
            StringMatch sm;
            sm.identifier = string->identifier;
            sm.offset = static_cast<std::uint64_t>(match->base + match->offset);
            sm.length = static_cast<std::uint32_t>(match->match_length);
            sm.excerpt = excerpt_of(match->data, static_cast<std::size_t>(match->data_length));
            m.strings.push_back(std::move(sm));
            ++taken;
        }
    }
    state->result->matches.push_back(std::move(m));
    return CALLBACK_CONTINUE;
}

}  // namespace

Rules::Rules(void* handle) : handle_(handle) { rule_count_ = count_rules(static_cast<YR_RULES*>(handle)); }

Rules::~Rules() {
    if (handle_ != nullptr) yr_rules_destroy(static_cast<YR_RULES*>(handle_));
}

std::shared_ptr<Rules> Rules::compile_source(const std::string& source, CompileReport& report, const std::string& ns) {
    CompilerMessages msgs{&report.errors, &report.warnings, "<source>"};
    Compiler compiler(msgs);
    if (yr_compiler_add_string(compiler.get(), source.c_str(), ns.c_str()) != 0) {
        report.ok = false;
        return nullptr;
    }
    YR_RULES* rules = nullptr;
    if (yr_compiler_get_rules(compiler.get(), &rules) != ERROR_SUCCESS) {
        report.errors.emplace_back("falha ao gerar regras compiladas");
        return nullptr;
    }
    auto out = std::shared_ptr<Rules>(new Rules(rules));
    report.ok = true;
    report.rule_count = out->rule_count();
    return out;
}

std::shared_ptr<Rules> Rules::compile_files(const std::vector<std::filesystem::path>& files, CompileReport& report) {
    std::vector<std::pair<std::filesystem::path, std::string>> good;
    for (const auto& file : files) {
        std::string source;
        try {
            source = read_text(file);
        } catch (const Error& e) {
            report.errors.emplace_back(e.what());
            continue;
        }
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        CompilerMessages msgs{&errors, &warnings, path_utf8(file.filename())};
        Compiler probe(msgs);
        if (yr_compiler_add_string(probe.get(), source.c_str(), "probe") != 0) {
            for (auto& e : errors) report.errors.push_back(path_utf8(file.filename()) + ": " + e);
            continue;
        }
        for (auto& w : warnings) report.warnings.push_back(path_utf8(file.filename()) + ": " + w);
        good.emplace_back(file, std::move(source));
    }
    if (good.empty()) {
        if (report.errors.empty()) report.errors.emplace_back("nenhum arquivo de regras YARA encontrado");
        report.ok = false;
        return nullptr;
    }
    std::vector<std::string> sink;
    CompilerMessages msgs{&report.errors, &sink, ""};
    Compiler compiler(msgs);
    for (std::size_t i = 0; i < good.size(); ++i) {
        msgs.current_file = path_utf8(good[i].first.filename());
        const std::string ns = "ns" + std::to_string(i);
        if (yr_compiler_add_string(compiler.get(), good[i].second.c_str(), ns.c_str()) != 0) {
            report.ok = false;  // cannot happen after the per-file probe, kept for safety
            return nullptr;
        }
        report.files.push_back(path_utf8(good[i].first));
    }
    YR_RULES* rules = nullptr;
    if (yr_compiler_get_rules(compiler.get(), &rules) != ERROR_SUCCESS) {
        report.errors.emplace_back("falha ao gerar regras compiladas");
        return nullptr;
    }
    auto out = std::shared_ptr<Rules>(new Rules(rules));
    report.ok = report.errors.empty();
    report.rule_count = out->rule_count();
    return out;
}

std::shared_ptr<Rules> Rules::load(const std::filesystem::path& compiled) {
    ensure_initialized();
    YR_RULES* rules = nullptr;
    if (yr_rules_load(path_utf8(compiled).c_str(), &rules) != ERROR_SUCCESS) {
        throw Error(ErrorCode::InvalidFormat, "regras compiladas inválidas: " + path_utf8(compiled));
    }
    return std::shared_ptr<Rules>(new Rules(rules));
}

std::vector<std::pair<std::string, std::map<std::string, std::string>>> Rules::metadata() const {
    std::vector<std::pair<std::string, std::map<std::string, std::string>>> out;
    YR_RULE* rule = nullptr;
    yr_rules_foreach(static_cast<YR_RULES*>(handle_), rule) { out.emplace_back(rule->identifier, meta_of(rule)); }
    return out;
}

void Rules::save(const std::filesystem::path& compiled) const {
    if (yr_rules_save(static_cast<YR_RULES*>(handle_), path_utf8(compiled).c_str()) != ERROR_SUCCESS) {
        throw Error(ErrorCode::FileAccess, "não foi possível salvar regras em " + path_utf8(compiled));
    }
}

ScanResult Rules::scan(ByteView data, const ScanOptions& options) const {
    ScanResult result;
    YR_SCANNER* scanner = nullptr;
    if (yr_scanner_create(static_cast<YR_RULES*>(handle_), &scanner) != ERROR_SUCCESS) {
        result.error = "falha ao criar o scanner YARA";
        return result;
    }
    ScanState state{&options, &result};
    yr_scanner_set_callback(scanner, scan_callback, &state);
    yr_scanner_set_timeout(scanner, options.timeout_seconds);
    yr_scanner_set_flags(scanner, SCAN_FLAGS_REPORT_RULES_MATCHING);
    yr_scanner_define_string_variable(scanner, "filename", options.externals.filename.c_str());
    yr_scanner_define_string_variable(scanner, "filepath", options.externals.filepath.c_str());
    yr_scanner_define_string_variable(scanner, "extension", options.externals.extension.c_str());
    yr_scanner_define_string_variable(scanner, "filetype", options.externals.filetype.c_str());
    static const std::uint8_t kEmpty = 0;
    const int rc = yr_scanner_scan_mem(scanner, data.empty() ? &kEmpty : data.data(), data.size());
    yr_scanner_destroy(scanner);
    if (rc == ERROR_SCAN_TIMEOUT) {
        result.timed_out = true;
    } else if (rc == ERROR_CALLBACK_ERROR || (rc != ERROR_SUCCESS && result.cancelled)) {
        result.cancelled = true;
    } else if (rc != ERROR_SUCCESS) {
        result.error = "erro do YARA " + std::to_string(rc);
    }
    return result;
}

std::vector<std::filesystem::path> rule_files_in(const std::filesystem::path& dir) {
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) return files;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
             dir, std::filesystem::directory_options::skip_permission_denied, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        const std::string ext = extension_of(entry.path());
        if (ext == ".yar" || ext == ".yara") files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());
    return files;
}

CompileReport validate_rules_dir(const std::filesystem::path& dir, const std::vector<std::string>& required_meta) {
    CompileReport report;
    const auto files = rule_files_in(dir);
    if (files.empty()) {
        report.errors.emplace_back("o pacote não contém arquivos .yar/.yara");
        return report;
    }
    auto rules = Rules::compile_files(files, report);
    if (rules) {
        for (const auto& [name, meta] : rules->metadata()) {
            for (const auto& key : required_meta) {
                if (!meta.contains(key)) report.errors.push_back("regra " + name + " sem metadado obrigatório '" + key + "'");
            }
        }
    }
    report.ok = rules != nullptr && report.errors.empty();
    return report;
}

std::string version() { return YR_VERSION; }

}  // namespace gk::yara
