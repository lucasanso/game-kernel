// Per-object analysis: turns bytes into context-free evidence (no folder context, no risk verdict).
// Folder context (cracks, mods) and the risk verdict are applied afterwards by the risk engine (M7).
#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gk/archive.hpp"
#include "gk/byte_view.hpp"
#include "gk/cancel.hpp"
#include "gk/model.hpp"
#include "gk/pe.hpp"
#include "gk/yara_engine.hpp"

namespace gk::analysis {

struct RuleSet {
    std::shared_ptr<yara::Rules> detection;    // signatures/yara (+ active package)
    std::shared_ptr<yara::Rules> indicators;   // signatures/internal/indicators.yar
    yara::CompileReport detection_report;
    yara::CompileReport indicator_report;

    // Detection rule files from every directory (later directories override files with the same name).
    static RuleSet load(const std::vector<std::filesystem::path>& detection_dirs,
                        const std::filesystem::path& indicator_file);
};

struct Options {
    bool deep = true;                          // archives, embedded payloads, script decoding
    archive::Limits archive_limits;
    std::uint64_t max_analysis_bytes = 512ull << 20;   // larger objects: header-level analysis only
    std::size_t max_script_bytes = 8u << 20;
    int yara_timeout_seconds = 60;
};

struct Subject {
    std::string path;                          // physical path or "container::member"
    std::string name;                          // file name (extension drives some rules)
    std::string directory;
    std::optional<std::string> container;      // top-level physical file for archive members
    std::optional<std::string> member_path;
    int depth = 0;
};

struct Output {
    FileResult result;
    std::vector<FileResult> members;           // archive members (any depth), each analysed
};

Output analyze(ByteView data, const Subject& subject, const RuleSet& rules, const Options& options,
               CancelToken* cancel = nullptr);
Output analyze_file(const std::filesystem::path& path, const RuleSet& rules, const Options& options,
                    CancelToken* cancel = nullptr);

// ---- building blocks (exposed for tests) -------------------------------------------------------

struct IndicatorHit {
    std::string id;                            // indicator id (rule name without "IND_")
    std::string group;
    std::string description;
    std::vector<Location> locations;
    std::vector<std::string> matched;          // distinct matched texts
};

// Structural evidence of a parsed PE and the features later used by folder context.
void pe_evidence(const pe::PeInfo& info, ByteView data, const Subject& subject, std::vector<Evidence>& out,
                 FileFeatures& features);
// Name-based deception (system process names, typosquats, double extensions, RLO) for any file.
void name_evidence(const Subject& subject, bool executable_content, std::vector<Evidence>& out);
// Capability correlation of indicator hits with imports (pe may be null for scripts/data).
void capability_evidence(const std::vector<IndicatorHit>& hits, const pe::PeInfo* pe, bool is_script,
                         const std::vector<Location>& network_literals, std::vector<Evidence>& out);
// IPv4:port literals (ASCII and UTF-16LE), excluding loopback/unspecified/broadcast.
std::vector<Location> network_literals(ByteView data, std::size_t max_hits = 20);

struct LnkInfo {
    bool valid = false;
    std::string target;                        // local base path or relative path
    std::string arguments;
    std::string working_dir;
    std::string icon_location;
    std::string name;
};
LnkInfo parse_lnk(ByteView data);

// Text of a script decoded to UTF-8 (BOM-aware: UTF-8, UTF-16LE/BE); invalid bytes kept as Latin-1.
std::string script_text(ByteView data, std::size_t max_bytes);
// PowerShell -EncodedCommand / FromBase64String payloads decoded from a script (UTF-16LE or UTF-8 text).
struct DecodedPayload {
    std::uint32_t line = 0;
    std::string kind;                          // encoded_command | base64_blob
    std::string text;                          // decoded text (UTF-8) when printable
    bool is_pe = false;
};
std::vector<DecodedPayload> decode_script_payloads(const std::string& text);

}  // namespace gk::analysis
