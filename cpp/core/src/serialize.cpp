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

}  // namespace gk
