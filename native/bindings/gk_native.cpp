// gk_native — thin pybind11 mirror of the Game Kernel C++ core (docs/INTEGRATION.md §2).
// No logic lives here: functions convert arguments, release the GIL for long operations and
// translate C++ exceptions into Python exceptions.
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl/filesystem.h>

#include <string>

#include "gk/archive.hpp"
#include "gk/error.hpp"
#include "gk/filetype.hpp"
#include "gk/file_view.hpp"
#include "gk/hash.hpp"
#include "gk/pe.hpp"
#include "gk/serialize.hpp"
#include "gk/version.hpp"
#include "gk/yara_engine.hpp"

namespace py = pybind11;

namespace {

gk::ByteView view_of(const py::bytes& b, std::string& storage) {
    storage = static_cast<std::string>(b);
    return gk::ByteView(storage);
}

// Contract documents are produced once, in C++ (gk/serialize.hpp), and handed to Python through the
// standard json module so Python receives exactly what the IPC channel would carry.
py::object json_to_py(const nlohmann::json& j) {
    static py::object loads = py::module_::import("json").attr("loads");
    return loads(j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
}

py::dict type_to_dict(const gk::TypeInfo& t) {
    py::dict d;
    d["kind"] = t.kind;
    d["description"] = t.description;
    d["group"] = t.group;
    d["disguised"] = t.disguised;
    return d;
}

gk::TypeInfo type_from_dict(const py::dict& d) {
    gk::TypeInfo t;
    t.kind = d["kind"].cast<std::string>();
    t.description = d.contains("description") ? d["description"].cast<std::string>() : std::string();
    t.group = d["group"].cast<std::string>();
    t.disguised = d.contains("disguised") && d["disguised"].cast<bool>();
    return t;
}

py::dict report_to_dict(const gk::yara::CompileReport& r) {
    py::dict d;
    d["ok"] = r.ok;
    d["rule_count"] = r.rule_count;
    d["errors"] = r.errors;
    d["warnings"] = r.warnings;
    d["files"] = r.files;
    return d;
}

py::list matches_to_list(const gk::yara::ScanResult& result) {
    py::list out;
    for (const auto& m : result.matches) {
        py::dict d;
        d["rule"] = m.rule;
        d["namespace"] = m.ns;
        d["tags"] = m.tags;
        d["meta"] = m.meta;
        py::list strings;
        for (const auto& s : m.strings) {
            py::dict sd;
            sd["identifier"] = s.identifier;
            sd["offset"] = s.offset;
            sd["length"] = s.length;
            sd["excerpt"] = s.excerpt;
            strings.append(sd);
        }
        d["strings"] = strings;
        out.append(d);
    }
    return out;
}

gk::FileTypeFilter filter_from_dict(const py::dict& d) {
    gk::FileTypeFilter f;
    auto get = [&](const char* key, bool& field) {
        if (d.contains(key)) field = d[key].cast<bool>();
    };
    get("executables", f.executables);
    get("libraries", f.libraries);
    get("drivers", f.drivers);
    get("scripts", f.scripts);
    get("archives", f.archives);
    get("installers", f.installers);
    get("java", f.java);
    get("shortcuts", f.shortcuts);
    get("data_sniffing", f.data_sniffing);
    return f;
}

}  // namespace

PYBIND11_MODULE(gk_native, m) {
    m.doc() = "Game Kernel native core (C++20)";
    m.attr("API_VERSION") = gk::kNativeApiVersion;
    m.attr("CORE_VERSION") = gk::kVersion;

    static py::exception<gk::Error> gk_error(m, "GkError", PyExc_RuntimeError);
    py::register_exception_translator([](std::exception_ptr p) {
        try {
            if (p) std::rethrow_exception(p);
        } catch (const gk::Error& e) {
            // args = (code, message) so Python code can inspect e.args[0].
            py::tuple args = py::make_tuple(static_cast<int>(e.code()), std::string(e.what()));
            PyErr_SetObject(gk_error.ptr(), args.ptr());
        }
    });

    m.def("sha256_bytes", [](const py::bytes& data) {
        std::string storage;
        const gk::ByteView v = view_of(data, storage);
        py::gil_scoped_release release;
        return gk::sha256_hex(v);
    });
    m.def("md5_bytes", [](const py::bytes& data) {
        std::string storage;
        const gk::ByteView v = view_of(data, storage);
        py::gil_scoped_release release;
        return gk::md5_hex(v);
    });
    m.def("sha256_file", [](const std::filesystem::path& path) {
        gk::FileHashes h;
        {
            py::gil_scoped_release release;
            h = gk::hash_file(path, false);
        }
        return h.sha256;
    });
    m.def(
        "hash_file",
        [](const std::filesystem::path& path, bool with_md5) {
            gk::FileHashes h;
            {
                py::gil_scoped_release release;
                h = gk::hash_file(path, with_md5);
            }
            py::dict d;
            d["sha256"] = h.sha256;
            d["md5"] = with_md5 ? py::object(py::str(h.md5)) : py::object(py::none());
            d["size"] = h.size;
            return d;
        },
        py::arg("path"), py::arg("with_md5") = true);

    m.def(
        "identify",
        [](const py::bytes& header, const std::string& extension, const py::bytes& iso_probe) {
            std::string hs;
            std::string ps;
            const gk::ByteView h = view_of(header, hs);
            const gk::ByteView p = view_of(iso_probe, ps);
            return type_to_dict(gk::identify(h, extension, p));
        },
        py::arg("header"), py::arg("extension"), py::arg("iso_probe") = py::bytes());
    m.def("identify_file", [](const std::filesystem::path& path) {
        gk::TypeInfo t;
        {
            py::gil_scoped_release release;
            t = gk::identify_file(path);
        }
        return type_to_dict(t);
    });
    m.def("group_enabled", [](const py::dict& info, const py::dict& file_types) {
        return gk::group_enabled(type_from_dict(info), filter_from_dict(file_types));
    });
    m.def("priority", [](const py::dict& info, const std::string& name) {
        return gk::priority(type_from_dict(info), name);
    });
    m.def("parse_pe", [](const py::bytes& data) {
        std::string storage;
        const gk::ByteView v = view_of(data, storage);
        nlohmann::json j;
        {
            py::gil_scoped_release release;
            j = gk::to_json(gk::pe::parse(v));
        }
        return json_to_py(j);
    });
    m.def("parse_pe_file", [](const std::filesystem::path& path) {
        nlohmann::json j;
        {
            py::gil_scoped_release release;
            const gk::MappedFile file = gk::MappedFile::open(path);
            j = gk::to_json(gk::pe::parse(file.view()));
        }
        return json_to_py(j);
    });
    m.def("pe_rva_to_offset", [](const py::bytes& data, const std::vector<std::uint32_t>& rvas) {
        std::string storage;
        const gk::pe::PeInfo info = gk::pe::parse(view_of(data, storage));
        std::vector<std::optional<std::uint64_t>> out;
        for (std::uint32_t rva : rvas) out.push_back(info.rva_to_offset(rva));
        return out;
    });
    m.def("pe_offset_to_rva", [](const py::bytes& data, const std::vector<std::uint64_t>& offsets) {
        std::string storage;
        const gk::pe::PeInfo info = gk::pe::parse(view_of(data, storage));
        std::vector<std::pair<std::optional<std::string>, std::optional<std::uint32_t>>> out;
        for (std::uint64_t off : offsets) {
            auto sec = info.section_for_offset(off);
            out.emplace_back(sec ? std::optional<std::string>(info.sections[*sec].name) : std::nullopt,
                             info.offset_to_rva(off));
        }
        return out;
    });
    m.def("shannon_entropy", [](const py::bytes& data) {
        std::string storage;
        return gk::pe::shannon_entropy(view_of(data, storage));
    });
    py::class_<gk::yara::Rules, std::shared_ptr<gk::yara::Rules>>(m, "YaraRules")
        .def_static(
            "compile_source",
            [](const std::string& source) {
                gk::yara::CompileReport report;
                auto rules = gk::yara::Rules::compile_source(source, report);
                return py::make_tuple(rules ? py::cast(rules) : py::none(), report_to_dict(report));
            })
        .def_static(
            "compile_files",
            [](const std::vector<std::filesystem::path>& files) {
                gk::yara::CompileReport report;
                std::shared_ptr<gk::yara::Rules> rules;
                {
                    py::gil_scoped_release release;
                    rules = gk::yara::Rules::compile_files(files, report);
                }
                return py::make_tuple(rules ? py::cast(rules) : py::none(), report_to_dict(report));
            })
        .def_static("load", &gk::yara::Rules::load)
        .def("save", &gk::yara::Rules::save)
        .def_property_readonly("rule_count", &gk::yara::Rules::rule_count)
        .def("metadata", &gk::yara::Rules::metadata)
        .def(
            "scan",
            [](const gk::yara::Rules& self, const py::bytes& data, const std::string& filename,
               const std::string& filepath, const std::string& extension, const std::string& filetype,
               int timeout, std::size_t max_instances, std::size_t max_strings) {
                std::string storage;
                const gk::ByteView v = view_of(data, storage);
                gk::yara::ScanOptions options;
                options.externals = {filename, filepath, extension, filetype};
                options.timeout_seconds = timeout;
                options.max_instances_per_string = max_instances;
                options.max_strings_per_rule = max_strings;
                gk::yara::ScanResult result;
                {
                    py::gil_scoped_release release;
                    result = self.scan(v, options);
                }
                py::dict d;
                d["matches"] = matches_to_list(result);
                d["timed_out"] = result.timed_out;
                d["cancelled"] = result.cancelled;
                d["truncated"] = result.truncated;
                d["error"] = result.error;
                return d;
            },
            py::arg("data"), py::arg("filename") = "", py::arg("filepath") = "", py::arg("extension") = "",
            py::arg("filetype") = "", py::arg("timeout") = 60, py::arg("max_instances") = 3,
            py::arg("max_strings") = 16);
    m.def("yara_validate_dir", [](const std::filesystem::path& dir) {
        gk::yara::CompileReport report;
        {
            py::gil_scoped_release release;
            report = gk::yara::validate_rules_dir(dir);
        }
        return report_to_dict(report);
    });
    m.def("yara_version", &gk::yara::version);

    m.def(
        "archive_walk",
        [](const py::bytes& data, const py::dict& limits) {
            std::string storage;
            const gk::ByteView v = view_of(data, storage);
            gk::archive::Limits lim;
            if (limits.contains("max_total_bytes")) lim.max_total_bytes = limits["max_total_bytes"].cast<std::uint64_t>();
            if (limits.contains("max_member_bytes")) lim.max_member_bytes = limits["max_member_bytes"].cast<std::uint64_t>();
            if (limits.contains("max_members")) lim.max_members = limits["max_members"].cast<std::uint64_t>();
            if (limits.contains("max_ratio")) lim.max_ratio = limits["max_ratio"].cast<double>();
            if (limits.contains("ratio_min_bytes")) lim.ratio_min_bytes = limits["ratio_min_bytes"].cast<std::uint64_t>();
            if (limits.contains("max_depth")) lim.max_depth = limits["max_depth"].cast<unsigned>();
            struct Row {
                gk::archive::Member member;
                std::string sha256;
                gk::TypeInfo type;
                bool has_data = false;
            };
            std::vector<Row> rows;
            gk::archive::Visitor visitor;
            visitor.on_entry = [&](const gk::archive::Member& member) {
                rows.push_back(Row{member, {}, {}, false});
                return gk::archive::Want::Read;
            };
            visitor.on_data = [&](const gk::archive::Member& member, gk::ByteView d) {
                Row& row = rows.back();
                row.member = member;
                row.sha256 = gk::sha256_hex(d);
                const std::string name = member.name.substr(member.name.find_last_of('/') == std::string::npos ? 0 : member.name.find_last_of('/') + 1);
                const auto dot = name.find_last_of('.');
                row.type = gk::identify(d.prefix(gk::kHeaderSize), dot == std::string::npos ? "" : name.substr(dot),
                                        d.clamp(gk::kIsoProbeOffset, gk::kIsoProbeSize));
                row.has_data = true;
            };
            visitor.is_archive = [&](const gk::archive::Member&, gk::ByteView) {
                const std::string& kind = rows.back().type.kind;
                return kind == "zip" || kind == "jar" || kind == "7z" || kind == "rar" || kind == "gzip" ||
                       kind == "bzip2" || kind == "xz" || kind == "tar" || kind == "cab" || kind == "iso" || kind == "zstd";
            };
            gk::archive::Report report;
            {
                py::gil_scoped_release release;
                report = gk::archive::walk(v, lim, visitor);
            }
            py::list members;
            for (const Row& row : rows) {
                const auto& mm = row.member;
                py::dict d;
                d["path"] = mm.path;
                d["name"] = mm.name;
                d["depth"] = mm.depth;
                d["declared_size"] = mm.size_known ? py::object(py::int_(mm.declared_size)) : py::object(py::none());
                d["bytes_read"] = mm.bytes_read;
                d["is_directory"] = mm.is_directory;
                d["is_symlink"] = mm.is_symlink;
                d["link_target"] = mm.link_target;
                d["encrypted"] = mm.encrypted;
                d["complete"] = mm.complete;
                d["anomalies"] = mm.anomalies;
                d["sha256"] = row.has_data ? py::object(py::str(row.sha256)) : py::object(py::none());
                d["kind"] = row.has_data ? py::object(py::str(row.type.kind)) : py::object(py::none());
                members.append(d);
            }
            py::dict out;
            out["format"] = report.format;
            out["nested_formats"] = report.nested_formats;
            out["members_seen"] = report.members_seen;
            out["total_bytes"] = report.total_bytes;
            out["complete"] = report.complete;
            out["encrypted_entries"] = report.encrypted_entries;
            out["anomalies"] = report.anomalies;
            out["errors"] = report.errors;
            out["members"] = members;
            return out;
        },
        py::arg("data"), py::arg("limits") = py::dict());
    m.def("archive_recognised", [](const py::bytes& data) {
        std::string storage;
        return gk::archive::recognised(view_of(data, storage));
    });
    m.def("libarchive_version", &gk::archive::libarchive_version);
    m.def("extension_of", [](const std::filesystem::path& path) { return gk::extension_of(path); });
}
