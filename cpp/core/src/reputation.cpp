#include <algorithm>
#include <cctype>

#include <nlohmann/json.hpp>

#include "gk/error.hpp"
#include "gk/file_view.hpp"
#include "gk/scan_support.hpp"
#include "gk/text.hpp"

namespace gk::scan {

namespace {
bool valid_sha256(const std::string& s) {
    return s.size() == 64 && std::all_of(s.begin(), s.end(), [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); });
}
}  // namespace

IocDb IocDb::load(const std::vector<std::filesystem::path>& dirs, std::vector<std::string>* errors) {
    IocDb db;
    for (const auto& dir : dirs) {
        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec)) continue;
        std::vector<std::filesystem::path> files;
        for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
            if (e.is_regular_file(ec) && lower_ascii(text::path_utf8(e.path().extension())) == ".json") files.push_back(e.path());
        }
        std::sort(files.begin(), files.end());
        for (const auto& f : files) {
            try {
                const auto bytes = read_range(f, 0, 64u << 20);
                const auto j = nlohmann::json::parse(bytes.begin(), bytes.end());
                if (j.value("format", "") != "gamekernel-ioc") throw Error(ErrorCode::InvalidFormat, "formato não é gamekernel-ioc");
                db.version_ = j.value("version", db.version_);
                const auto entries = j.value("entries", nlohmann::json::array());
                for (const auto& e : entries) {
                    std::string sha = lower_ascii(e.value("sha256", ""));
                    const std::string verdict = e.value("verdict", "");
                    if (!valid_sha256(sha) || (verdict != "bad" && verdict != "good")) continue;
                    db.entries_[sha] = IocEntry{verdict, e.value("name", ""), e.value("category", "generic_malware"),
                                                e.value("severity", "HIGH"), e.value("source", ""), e.value("note", "")};
                }
            } catch (const std::exception& ex) {
                if (errors != nullptr) errors->push_back(text::path_utf8(f.filename()) + ": " + ex.what());
            }
        }
    }
    return db;
}

const IocEntry* IocDb::find(const std::string& sha256) const {
    auto it = entries_.find(lower_ascii(sha256));
    return it == entries_.end() ? nullptr : &it->second;
}

std::optional<Evidence> reputation_evidence(const std::string& verdict, const std::string& name,
                                            const std::string& category, const std::string& severity,
                                            const std::string& origin) {
    Evidence e;
    e.source = Source::Reputation;
    e.engine = "reputation";
    e.confidence = Confidence::High;
    Location l;
    l.kind = "header";
    l.description = "SHA-256 do arquivo inteiro";
    e.locations.push_back(l);
    e.details["origem"] = origin;
    if (verdict == "bad") {
        e.rule_id = "REPUTATION.KnownBad";
        e.title = "Hash de ameaça conhecida" + (name.empty() ? std::string() : ": " + name);
        e.category = category::known(category) ? category : std::string(category::kGenericMalware);
        e.severity = parse_risk(severity, Risk::High);
        e.description = "O SHA-256 deste arquivo está na base local de ameaças (" + origin + ").";
        e.details["verdict"] = category == category::kTestFile ? "test" : "malware";
        e.fp_note = "Só é falso positivo se a base local estiver errada.";
        return e;
    }
    if (verdict == "good") {
        e.rule_id = "REPUTATION.KnownGood";
        e.title = "Arquivo conhecido como legítimo" + (name.empty() ? std::string() : ": " + name);
        e.category = std::string(category::kInformational);
        e.severity = Risk::Info;
        e.description = "O SHA-256 está na base local de arquivos legítimos (" + origin + ").";
        e.details["verdict"] = "good";
        return e;
    }
    return std::nullopt;
}

}  // namespace gk::scan
