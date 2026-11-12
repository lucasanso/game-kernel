#include "gk/model.hpp"

#include <algorithm>
#include <array>

#include "gk/text.hpp"

namespace gk {

namespace category {
bool known(std::string_view v) {
    static constexpr std::array kAll = {kTrojan, kRat, kKeylogger, kSpyware, kPasswordStealer, kCookieStealer,
                                        kRansomware, kCryptominer, kBackdoor, kRootkit, kLoader, kDropper,
                                        kDownloader, kDllHijacking, kProcessInjection, kPersistence,
                                        kMaliciousScript, kObfuscation, kSystemModification, kCredentialAccess,
                                        kStealth, kNetwork, kDefenseEvasion, kPua, kGenericMalware,
                                        kCrackComponent, kModComponent, kStructural, kTestFile, kInformational};
    return std::find(kAll.begin(), kAll.end(), v) != kAll.end();
}
}  // namespace category

std::string_view name_of(Risk r) {
    switch (r) {
        case Risk::None: return "NONE";
        case Risk::Info: return "INFO";
        case Risk::Low: return "LOW";
        case Risk::Medium: return "MEDIUM";
        case Risk::High: return "HIGH";
        case Risk::Critical: return "CRITICAL";
    }
    return "NONE";
}

std::string_view name_of(Confidence c) {
    switch (c) {
        case Confidence::Low: return "LOW";
        case Confidence::Medium: return "MEDIUM";
        case Confidence::High: return "HIGH";
    }
    return "LOW";
}

std::string_view value_of(Source s) {
    switch (s) {
        case Source::Signature: return "signature";
        case Source::Yara: return "yara";
        case Source::Static: return "static";
        case Source::Behavioral: return "behavioral";
        case Source::Reputation: return "reputation";
        case Source::Heuristic: return "heuristic";
        case Source::Context: return "context";
    }
    return "heuristic";
}

std::string_view value_of(Classification c) {
    switch (c) {
        case Classification::KnownLegit: return "known_legit";
        case Classification::Unknown: return "unknown";
        case Classification::Modified: return "modified";
        case Classification::Pua: return "pua";
        case Classification::Suspicious: return "suspicious";
        case Classification::Malware: return "malware";
        case Classification::Inconclusive: return "inconclusive";
    }
    return "unknown";
}

std::string_view value_of(CrackStatus c) {
    switch (c) {
        case CrackStatus::None: return "none";
        case CrackStatus::RecognizedClean: return "recognized_clean";
        case CrackStatus::Unknown: return "unknown";
        case CrackStatus::Suspicious: return "suspicious";
        case CrackStatus::Malware: return "malware";
        case CrackStatus::Insufficient: return "insufficient";
        case CrackStatus::ModifiedNoThreat: return "modified_no_threat";
    }
    return "none";
}

std::string_view value_of(AnalysisStatus s) {
    switch (s) {
        case AnalysisStatus::Complete: return "complete";
        case AnalysisStatus::Partial: return "partial";
        case AnalysisStatus::Skipped: return "skipped";
        case AnalysisStatus::Error: return "error";
    }
    return "complete";
}

Risk parse_risk(std::string_view text, Risk fallback) {
    std::string t(text);
    std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    if (t == "NONE") return Risk::None;
    if (t == "INFO") return Risk::Info;
    if (t == "LOW") return Risk::Low;
    if (t == "MEDIUM") return Risk::Medium;
    if (t == "HIGH") return Risk::High;
    if (t == "CRITICAL") return Risk::Critical;
    return fallback;
}

Confidence parse_confidence(std::string_view text, Confidence fallback) {
    std::string t(text);
    std::transform(t.begin(), t.end(), t.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    if (t == "LOW") return Confidence::Low;
    if (t == "MEDIUM") return Confidence::Medium;
    if (t == "HIGH") return Confidence::High;
    return fallback;
}

Risk lower(Risk r, int steps) {
    if (r == Risk::None) return r;
    const int v = std::max(static_cast<int>(Risk::Info), static_cast<int>(r) - steps);
    return static_cast<Risk>(v);
}

namespace {
std::string excerpt_from_codepoints(const std::u32string& cps, std::size_t limit) {
    std::string out;
    for (std::size_t i = 0; i < cps.size() && i < limit; ++i) {
        const char32_t cp = cps[i];
        if (cp == '\r' || cp == '\n' || cp == '\t') {
            out.push_back(' ');
        } else if ((cp >= 32 && cp < 127) || cp >= 160) {
            text::append_utf8(out, static_cast<std::uint32_t>(cp));
        } else {
            out.push_back('.');
        }
    }
    if (cps.size() > limit) out += "\xE2\x80\xA6";
    return out;
}
}  // namespace

std::string printable_excerpt_bytes(std::string_view bytes, std::size_t limit) {
    std::u32string cps;
    cps.reserve(std::min(bytes.size(), limit + 1));
    for (std::size_t i = 0; i < bytes.size() && i <= limit; ++i) cps.push_back(static_cast<unsigned char>(bytes[i]));
    return excerpt_from_codepoints(cps, limit);
}

std::string printable_excerpt_text(std::string_view utf8, std::size_t limit) {
    std::u32string cps;
    for (std::size_t i = 0; i < utf8.size() && cps.size() <= limit;) {
        const auto c = static_cast<unsigned char>(utf8[i]);
        char32_t cp = c;
        std::size_t len = 1;
        if (c >= 0xF0 && c < 0xF8) {
            cp = c & 0x07;
            len = 4;
        } else if (c >= 0xE0) {
            cp = c & 0x0F;
            len = 3;
        } else if (c >= 0xC0) {
            cp = c & 0x1F;
            len = 2;
        } else if (c >= 0x80) {
            cp = 0xFFFD;
        }
        bool valid = i + len <= utf8.size();
        for (std::size_t k = 1; valid && k < len; ++k) {
            const auto cc = static_cast<unsigned char>(utf8[i + k]);
            if ((cc & 0xC0) != 0x80) valid = false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (!valid) {
            cp = 0xFFFD;
            len = 1;
        }
        cps.push_back(cp);
        i += len;
    }
    return excerpt_from_codepoints(cps, limit);
}

}  // namespace gk
