// Result model of the analysis core. Mirrors gamekernel/core/models.py field by field; the JSON produced
// by gk::to_json (serialize.hpp) must load with FileResult.from_dict() unchanged (tests/native/test_model.py).
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace gk {

enum class Risk : int { None = 0, Info = 1, Low = 2, Medium = 3, High = 4, Critical = 5 };
enum class Confidence : int { Low = 1, Medium = 2, High = 3 };
enum class Source { Signature, Yara, Static, Behavioral, Reputation, Heuristic, Context };
enum class Classification { KnownLegit, Unknown, Modified, Pua, Suspicious, Malware, Inconclusive };
enum class CrackStatus { None, RecognizedClean, Unknown, Suspicious, Malware, Insufficient, ModifiedNoThreat };
enum class AnalysisStatus { Complete, Partial, Skipped, Error };

// ThreatCategory values are the strings of models.py (e.g. "password_stealer"); kept as text so the
// catalog can grow through rule metadata without recompiling.
namespace category {
inline constexpr std::string_view kTrojan = "trojan", kRat = "rat", kKeylogger = "keylogger", kSpyware = "spyware",
    kPasswordStealer = "password_stealer", kCookieStealer = "cookie_stealer", kRansomware = "ransomware",
    kCryptominer = "cryptominer", kBackdoor = "backdoor", kRootkit = "rootkit", kLoader = "loader",
    kDropper = "dropper", kDownloader = "downloader", kDllHijacking = "dll_hijacking",
    kProcessInjection = "process_injection", kPersistence = "persistence", kMaliciousScript = "malicious_script",
    kObfuscation = "obfuscation", kSystemModification = "system_modification",
    kCredentialAccess = "credential_access", kStealth = "stealth", kNetwork = "network_communication",
    kDefenseEvasion = "defense_evasion", kPua = "pua", kGenericMalware = "generic_malware",
    kCrackComponent = "crack_component", kModComponent = "mod_component", kStructural = "structural_anomaly",
    kTestFile = "test_file", kInformational = "informational";
bool known(std::string_view value);
}  // namespace category

std::string_view name_of(Risk r);            // "NONE".."CRITICAL"
std::string_view name_of(Confidence c);      // "LOW".."HIGH"
std::string_view value_of(Source s);         // "signature"..
std::string_view value_of(Classification c);
std::string_view value_of(CrackStatus c);
std::string_view value_of(AnalysisStatus s);
Risk parse_risk(std::string_view text, Risk fallback = Risk::Info);
Confidence parse_confidence(std::string_view text, Confidence fallback = Confidence::Low);
Risk lower(Risk r, int steps = 1);           // never below Info (None stays None)

struct Location {
    std::string kind;                        // string | import | export | section | overlay | resource | header |
                                             // line | member | certificate | yara_match
    std::string description;
    std::optional<std::string> section;
    std::optional<std::uint64_t> offset;
    std::optional<std::uint32_t> rva;
    std::optional<std::uint32_t> length;
    std::optional<std::uint32_t> line;
    std::optional<std::string> excerpt;
};

struct Evidence {
    std::string rule_id;
    std::string title;
    Source source = Source::Heuristic;
    std::string category{category::kInformational};
    Risk severity = Risk::Info;
    Confidence confidence = Confidence::Low;
    std::string description;
    std::string engine;
    std::vector<Location> locations;
    std::map<std::string, std::string> details;   // textual details (JSON object of strings)
    std::string fp_note;
    std::vector<std::string> tags;
    std::optional<Risk> adjusted_severity;
    std::string adjustment_reason;

    [[nodiscard]] Risk effective() const { return adjusted_severity.value_or(severity); }
};

struct FileFeatures {
    std::string file_type = "unknown";
    bool is_pe = false, is_dll = false, is_driver = false, is_dotnet = false;
    std::optional<std::string> machine;
    bool signed_ = false;                    // serialized as "signed"
    std::optional<bool> signature_valid;
    std::optional<std::string> signer;
    std::map<std::string, std::string> version_info;
    std::vector<std::string> exports;
    std::vector<std::string> export_forwarders;
    std::vector<std::string> imports_dlls;
    std::vector<std::string> packers;
    std::optional<std::string> installer;
    std::vector<std::string> marker_strings;
    std::optional<std::string> text_head;
};

struct FileResult {
    std::string path, name, directory, extension;
    std::uint64_t size = 0;
    std::optional<std::string> sha256, md5;
    std::string file_type = "unknown";
    std::optional<std::string> container, member_path;
    int depth = 0;
    AnalysisStatus status = AnalysisStatus::Complete;
    std::vector<std::string> status_reasons;
    std::vector<Evidence> evidences;
    FileFeatures features;
    std::vector<std::string> engines;
    Risk risk = Risk::None;
    Classification classification = Classification::Unknown;
    CrackStatus crack_status = CrackStatus::None;
    std::optional<std::string> primary_category;
    std::vector<std::string> explanation, recommendations;
    bool possible_false_positive = false;
    double analyzed_at = 0.0;
    bool from_cache = false;
};

// Single-line excerpts with the exact rules of models.printable_excerpt: CR/LF/TAB -> space, code points
// 32..126 and >= 160 kept, everything else '.', "…" appended when truncated.
std::string printable_excerpt_bytes(std::string_view bytes, std::size_t limit = 160);   // bytes as Latin-1
std::string printable_excerpt_text(std::string_view utf8, std::size_t limit = 160);     // UTF-8 text

}  // namespace gk
