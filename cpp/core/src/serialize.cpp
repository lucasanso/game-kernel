#include "gk/serialize.hpp"

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

}  // namespace gk
