// gk_native — thin pybind11 mirror of the Game Kernel C++ core (docs/INTEGRATION.md §2).
// No logic lives here: functions convert arguments, release the GIL for long operations and
// translate C++ exceptions into Python exceptions.
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl/filesystem.h>

#include <string>

#include "gk/error.hpp"
#include "gk/filetype.hpp"
#include "gk/hash.hpp"
#include "gk/version.hpp"

namespace py = pybind11;

namespace {

gk::ByteView view_of(const py::bytes& b, std::string& storage) {
    storage = static_cast<std::string>(b);
    return gk::ByteView(storage);
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
    m.def("extension_of", [](const std::filesystem::path& path) { return gk::extension_of(path); });
}
