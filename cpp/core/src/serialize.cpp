#include "gk/serialize.hpp"

#include "gk/error.hpp"

namespace gk {

using nlohmann::json;

json to_json(const TypeInfo& t) {
    return json{{"kind", t.kind}, {"description", t.description}, {"group", t.group}, {"disguised", t.disguised}};
}

json to_json(const pe::PeInfo& p) {
    json j;
    j["valid"] = p.valid;
    j["error"] = p.error;
    j["anomalies"] = p.anomalies;
    j["file_size"] = p.file_size;
    j["e_lfanew"] = p.e_lfanew;
    j["machine"] = p.machine;
    j["machine_name"] = pe::machine_name(p.machine);
    j["number_of_sections"] = p.number_of_sections;
    j["timestamp"] = p.timestamp;
    j["characteristics"] = p.characteristics;
    j["magic"] = p.magic;
    j["is_64"] = p.is_64;
    j["is_dll"] = p.is_dll;
    j["is_driver"] = p.is_driver;
    j["is_dotnet"] = p.is_dotnet;
    j["entry_point"] = p.entry_point;
    j["entry_section"] = p.entry_section ? json(p.sections[*p.entry_section].name) : json(nullptr);
    j["image_base"] = p.image_base;
    j["section_alignment"] = p.section_alignment;
    j["file_alignment"] = p.file_alignment;
    j["size_of_image"] = p.size_of_image;
    j["size_of_headers"] = p.size_of_headers;
    j["checksum"] = p.checksum;
    j["subsystem"] = p.subsystem;
    j["dll_characteristics"] = p.dll_characteristics;
    j["number_of_rva_and_sizes"] = p.number_of_rva_and_sizes;
    json dirs = json::array();
    for (const auto& [rva, size] : p.data_directories) dirs.push_back(json{{"rva", rva}, {"size", size}});
    j["data_directories"] = dirs;

    json sections = json::array();
    for (const auto& s : p.sections) {
        sections.push_back(json{{"name", s.name},
                                {"virtual_address", s.virtual_address},
                                {"virtual_size", s.virtual_size},
                                {"raw_offset", s.raw_offset},
                                {"raw_size", s.raw_size},
                                {"data_size", s.data_size},
                                {"characteristics", s.characteristics},
                                {"entropy", s.entropy},
                                {"executable", s.executable},
                                {"writable", s.writable},
                                {"readable", s.readable},
                                {"contains_code", s.contains_code},
                                {"raw_beyond_eof", s.raw_beyond_eof},
                                {"header_index", s.header_index}});
    }
    j["sections"] = sections;

    json imports = json::array();
    for (const auto& i : p.imports) {
        imports.push_back(json{{"dll", i.dll},
                               {"name", i.name},
                               {"name_from_ordinal", i.name_from_ordinal},
                               {"ordinal", i.by_ordinal ? json(i.ordinal) : json(nullptr)},
                               {"hint", i.hint},
                               {"delayed", i.delayed},
                               {"iat_rva", i.iat_rva}});
    }
    j["imports"] = imports;

    json exports = json::array();
    for (const auto& e : p.exports) {
        exports.push_back(json{{"name", e.name}, {"ordinal", e.ordinal}, {"rva", e.rva}, {"forwarder", e.forwarder}});
    }
    j["exports"] = exports;
    j["export_name"] = p.export_name;

    json resources = json::array();
    for (const auto& r : p.resources) {
        resources.push_back(json{{"type", r.type},
                                 {"name", r.name},
                                 {"lang", r.lang},
                                 {"rva", r.rva},
                                 {"size", r.size},
                                 {"offset", r.offset ? json(*r.offset) : json(nullptr)},
                                 {"available", r.available},
                                 {"entropy", r.entropy ? json(*r.entropy) : json(nullptr)},
                                 {"magic", r.magic}});
    }
    j["resources"] = resources;
    j["version_info"] = p.version_info;
    j["manifest_execution_level"] = p.manifest_execution_level;
    j["tls_callbacks"] = p.tls_callbacks;
    json debug = json::array();
    for (const auto& d : p.debug) {
        debug.push_back(json{{"type", d.type}, {"pdb_path", d.pdb_path}, {"guid", d.guid}, {"age", d.age}});
    }
    j["debug"] = debug;
    j["has_rich_header"] = p.has_rich_header;
    j["security_offset"] = p.security_offset;
    j["security_size"] = p.security_size;
    j["overlay_offset"] = p.overlay_offset ? json(*p.overlay_offset) : json(nullptr);
    j["overlay_size"] = p.overlay_size;
    j["overlay_entropy"] = p.overlay_entropy;
    j["overlay_magic"] = p.overlay_magic;
    j["overlay_is_certificate_only"] = p.overlay_is_certificate_only;
    return j;
}

json to_json(const Location& l) {
    json j;
    j["kind"] = l.kind;
    if (!l.description.empty()) j["description"] = l.description;
    if (l.section && !l.section->empty()) j["section"] = *l.section;
    if (l.offset) j["offset"] = *l.offset;
    if (l.rva) j["rva"] = *l.rva;
    if (l.length) j["length"] = *l.length;
    if (l.line) j["line"] = *l.line;
    if (l.excerpt && !l.excerpt->empty()) j["excerpt"] = *l.excerpt;
    return j;
}

json to_json(const Evidence& e) {
    json locations = json::array();
    for (const auto& l : e.locations) locations.push_back(to_json(l));
    return json{{"rule_id", e.rule_id},
                {"title", e.title},
                {"source", value_of(e.source)},
                {"category", e.category},
                {"severity", name_of(e.severity)},
                {"confidence", name_of(e.confidence)},
                {"description", e.description},
                {"engine", e.engine},
                {"locations", locations},
                {"details", e.details},
                {"fp_note", e.fp_note},
                {"tags", e.tags},
                {"adjusted_severity", e.adjusted_severity ? json(name_of(*e.adjusted_severity)) : json(nullptr)},
                {"adjustment_reason", e.adjustment_reason}};
}

namespace {
template <typename T>
json opt(const std::optional<T>& v) {
    return v ? json(*v) : json(nullptr);
}
}  // namespace

json to_json(const FileFeatures& f) {
    return json{{"file_type", f.file_type},
                {"is_pe", f.is_pe},
                {"is_dll", f.is_dll},
                {"is_driver", f.is_driver},
                {"is_dotnet", f.is_dotnet},
                {"machine", opt(f.machine)},
                {"signed", f.signed_},
                {"signature_valid", opt(f.signature_valid)},
                {"signer", opt(f.signer)},
                {"version_info", f.version_info},
                {"exports", f.exports},
                {"export_forwarders", f.export_forwarders},
                {"imports_dlls", f.imports_dlls},
                {"packers", f.packers},
                {"installer", opt(f.installer)},
                {"marker_strings", f.marker_strings},
                {"text_head", opt(f.text_head)}};
}

json to_json(const FileResult& r) {
    json evidences = json::array();
    for (const auto& e : r.evidences) evidences.push_back(to_json(e));
    return json{{"path", r.path},
                {"name", r.name},
                {"directory", r.directory},
                {"extension", r.extension},
                {"size", r.size},
                {"sha256", opt(r.sha256)},
                {"md5", opt(r.md5)},
                {"file_type", r.file_type},
                {"container", opt(r.container)},
                {"member_path", opt(r.member_path)},
                {"depth", r.depth},
                {"status", value_of(r.status)},
                {"status_reasons", r.status_reasons},
                {"evidences", evidences},
                {"features", to_json(r.features)},
                {"engines", r.engines},
                {"risk", name_of(r.risk)},
                {"classification", value_of(r.classification)},
                {"crack_status", value_of(r.crack_status)},
                {"primary_category", opt(r.primary_category)},
                {"explanation", r.explanation},
                {"recommendations", r.recommendations},
                {"possible_false_positive", r.possible_false_positive},
                {"analyzed_at", r.analyzed_at},
                {"from_cache", r.from_cache}};
}

namespace {

template <typename T>
T get_or(const json& j, const char* key, T fallback) {
    auto it = j.find(key);
    if (it == j.end() || it->is_null()) return fallback;
    return it->get<T>();
}

template <typename T>
std::optional<T> get_opt(const json& j, const char* key) {
    auto it = j.find(key);
    if (it == j.end() || it->is_null()) return std::nullopt;
    return it->get<T>();
}

std::vector<std::string> strings(const json& j, const char* key) {
    std::vector<std::string> out;
    auto it = j.find(key);
    if (it != j.end() && it->is_array()) {
        for (const auto& v : *it) {
            if (v.is_string()) out.push_back(v.get<std::string>());
        }
    }
    return out;
}

Source parse_source(const std::string& v) {
    for (Source s : {Source::Signature, Source::Yara, Source::Static, Source::Behavioral, Source::Reputation,
                     Source::Heuristic, Source::Context}) {
        if (value_of(s) == v) return s;
    }
    throw Error(ErrorCode::InvalidFormat, "fonte de evidência desconhecida: " + v);
}

template <typename E>
E parse_enum(const std::string& v, std::initializer_list<E> all, const char* what) {
    for (E e : all) {
        if (value_of(e) == v) return e;
    }
    throw Error(ErrorCode::InvalidFormat, std::string(what) + " desconhecido: " + v);
}

}  // namespace

Location location_from_json(const json& j) {
    Location l;
    l.kind = get_or<std::string>(j, "kind", "string");
    l.description = get_or<std::string>(j, "description", "");
    l.section = get_opt<std::string>(j, "section");
    l.offset = get_opt<std::uint64_t>(j, "offset");
    l.rva = get_opt<std::uint32_t>(j, "rva");
    l.length = get_opt<std::uint32_t>(j, "length");
    l.line = get_opt<std::uint32_t>(j, "line");
    l.excerpt = get_opt<std::string>(j, "excerpt");
    return l;
}

Evidence evidence_from_json(const json& j) {
    if (!j.is_object() || !j.contains("rule_id")) throw Error(ErrorCode::InvalidFormat, "evidência sem rule_id");
    Evidence e;
    e.rule_id = j.at("rule_id").get<std::string>();
    e.title = get_or<std::string>(j, "title", e.rule_id);
    e.source = parse_source(get_or<std::string>(j, "source", "heuristic"));
    e.category = get_or<std::string>(j, "category", std::string(category::kInformational));
    e.severity = parse_risk(get_or<std::string>(j, "severity", "INFO"));
    e.confidence = parse_confidence(get_or<std::string>(j, "confidence", "LOW"));
    e.description = get_or<std::string>(j, "description", "");
    e.engine = get_or<std::string>(j, "engine", "");
    if (auto it = j.find("locations"); it != j.end() && it->is_array()) {
        for (const auto& l : *it) e.locations.push_back(location_from_json(l));
    }
    if (auto it = j.find("details"); it != j.end() && it->is_object()) {
        for (const auto& [k, v] : it->items()) e.details[k] = v.is_string() ? v.get<std::string>() : v.dump();
    }
    e.fp_note = get_or<std::string>(j, "fp_note", "");
    e.tags = strings(j, "tags");
    if (auto adj = get_opt<std::string>(j, "adjusted_severity")) e.adjusted_severity = parse_risk(*adj);
    e.adjustment_reason = get_or<std::string>(j, "adjustment_reason", "");
    return e;
}

FileFeatures features_from_json(const json& j) {
    FileFeatures f;
    if (!j.is_object()) return f;
    f.file_type = get_or<std::string>(j, "file_type", "unknown");
    f.is_pe = get_or(j, "is_pe", false);
    f.is_dll = get_or(j, "is_dll", false);
    f.is_driver = get_or(j, "is_driver", false);
    f.is_dotnet = get_or(j, "is_dotnet", false);
    f.machine = get_opt<std::string>(j, "machine");
    f.signed_ = get_or(j, "signed", false);
    f.signature_valid = get_opt<bool>(j, "signature_valid");
    f.signer = get_opt<std::string>(j, "signer");
    if (auto it = j.find("version_info"); it != j.end() && it->is_object()) {
        for (const auto& [k, v] : it->items()) {
            if (v.is_string()) f.version_info[k] = v.get<std::string>();
        }
    }
    f.exports = strings(j, "exports");
    f.export_forwarders = strings(j, "export_forwarders");
    f.imports_dlls = strings(j, "imports_dlls");
    f.packers = strings(j, "packers");
    f.installer = get_opt<std::string>(j, "installer");
    f.marker_strings = strings(j, "marker_strings");
    f.text_head = get_opt<std::string>(j, "text_head");
    return f;
}

FileResult file_result_from_json(const json& j) {
    if (!j.is_object() || !j.contains("path")) throw Error(ErrorCode::InvalidFormat, "resultado sem path");
    FileResult r;
    r.path = j.at("path").get<std::string>();
    r.name = get_or<std::string>(j, "name", "");
    r.directory = get_or<std::string>(j, "directory", "");
    r.extension = get_or<std::string>(j, "extension", "");
    r.size = get_or<std::uint64_t>(j, "size", 0);
    r.sha256 = get_opt<std::string>(j, "sha256");
    r.md5 = get_opt<std::string>(j, "md5");
    r.file_type = get_or<std::string>(j, "file_type", "unknown");
    r.container = get_opt<std::string>(j, "container");
    r.member_path = get_opt<std::string>(j, "member_path");
    r.depth = get_or(j, "depth", 0);
    r.status = parse_enum(get_or<std::string>(j, "status", "complete"),
                          {AnalysisStatus::Complete, AnalysisStatus::Partial, AnalysisStatus::Skipped, AnalysisStatus::Error},
                          "status");
    r.status_reasons = strings(j, "status_reasons");
    if (auto it = j.find("evidences"); it != j.end() && it->is_array()) {
        for (const auto& e : *it) r.evidences.push_back(evidence_from_json(e));
    }
    if (auto it = j.find("features"); it != j.end()) r.features = features_from_json(*it);
    r.engines = strings(j, "engines");
    r.risk = parse_risk(get_or<std::string>(j, "risk", "NONE"), Risk::None);
    r.classification = parse_enum(get_or<std::string>(j, "classification", "unknown"),
                                  {Classification::KnownLegit, Classification::Unknown, Classification::Modified,
                                   Classification::Pua, Classification::Suspicious, Classification::Malware,
                                   Classification::Inconclusive},
                                  "classificação");
    r.crack_status = parse_enum(get_or<std::string>(j, "crack_status", "none"),
                                {CrackStatus::None, CrackStatus::RecognizedClean, CrackStatus::Unknown,
                                 CrackStatus::Suspicious, CrackStatus::Malware, CrackStatus::Insufficient,
                                 CrackStatus::ModifiedNoThreat},
                                "estado de crack");
    r.primary_category = get_opt<std::string>(j, "primary_category");
    r.explanation = strings(j, "explanation");
    r.recommendations = strings(j, "recommendations");
    r.possible_false_positive = get_or(j, "possible_false_positive", false);
    r.analyzed_at = get_or(j, "analyzed_at", 0.0);
    r.from_cache = get_or(j, "from_cache", false);
    return r;
}

namespace {
nlohmann::json certificate_json(const authenticode::Certificate& c) {
    return {{"subject_cn", c.subject_cn}, {"subject_o", c.subject_o}, {"issuer_cn", c.issuer_cn},
            {"issuer_o", c.issuer_o},     {"serial", c.serial},       {"sha256", c.sha256},
            {"not_before", c.not_before}, {"not_after", c.not_after}, {"self_issued", c.self_issued}};
}
}  // namespace

nlohmann::json to_json(const authenticode::Report& report) {
    nlohmann::json sigs = nlohmann::json::array();
    for (const auto& s : report.signatures) {
        nlohmann::json certs = nlohmann::json::array();
        for (const auto& c : s.certificates) certs.push_back(certificate_json(c));
        sigs.push_back({{"depth", s.depth},
                        {"digest_algorithm", s.digest_algorithm},
                        {"signed_digest", s.signed_digest},
                        {"image_digest", s.image_digest ? nlohmann::json(*s.image_digest) : nlohmann::json()},
                        {"digest_matches", s.digest_matches},
                        {"signer", s.signer ? certificate_json(*s.signer) : nlohmann::json()},
                        {"certificates", certs},
                        {"timestamped", s.timestamped}});
    }
    return {{"present", report.present},
            {"table_offset", report.table_offset},
            {"table_size", report.table_size},
            {"signatures", sigs},
            {"anomalies", report.anomalies},
            {"bytes_after_table", report.bytes_after_table},
            {"hidden_bytes", report.hidden_bytes},
            {"tampered", report.tampered()},
            {"error", report.error ? nlohmann::json(*report.error) : nlohmann::json()}};
}

nlohmann::json to_json(const authenticode::TrustResult& t) {
    return {{"state", authenticode::value_of(t.state)},
            {"status_code", t.status_code},
            {"from_catalog", t.from_catalog},
            {"catalog", t.catalog},
            {"signer", t.signer},
            {"issuer", t.issuer},
            {"signer_thumbprint", t.signer_thumbprint},
            {"timestamp", t.timestamp},
            {"message", t.message}};
}

}  // namespace gk
