// Portable Executable parser for untrusted input.
//
// * Every read goes through ByteView (bounds-checked); every table walk has a hard limit.
// * Malformed structures never throw: they are recorded in `anomalies` and parsing continues
//   with whatever could be read safely.
// * RVA <-> file-offset mapping follows the Windows loader rules as implemented by pefile
//   (alignment adjustment, section sorting), which tests/native/test_pe.py checks for equivalence.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "gk/byte_view.hpp"

namespace gk::pe {

struct Limits {
    std::size_t max_sections = 0x800;
    std::size_t max_import_descriptors = 4096;
    std::size_t max_imports_per_dll = 0x2000;
    std::size_t max_imports_total = 0x4000;    // real binaries import a few thousand functions at most
    std::size_t max_exports = 0x10000;
    std::size_t max_resources = 0x8000;
    std::size_t max_resource_depth = 8;
    std::size_t max_name_length = 0x200;
    std::size_t max_tls_callbacks = 64;
    std::size_t max_debug_entries = 32;
    std::size_t max_version_bytes = 1 << 20;
    std::size_t max_manifest_bytes = 1 << 18;
    std::uint64_t resource_analysis_budget = 64ull << 20;   // bytes hashed for entropy across all resources
};

struct Section {
    std::string name;               // printable form (non-printable bytes escaped as \xNN)
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_offset = 0;   // PointerToRawData as stored
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;
    double entropy = 0.0;           // over the section's raw data (pefile semantics)
    std::uint64_t data_size = 0;    // bytes of raw data actually present in the file
    bool executable = false;
    bool writable = false;
    bool readable = false;
    bool contains_code = false;
    bool raw_beyond_eof = false;
    std::size_t header_index = 0;   // position in the section table
};

struct Import {
    std::string dll;                // as stored (case preserved)
    std::string name;               // empty for ordinal imports
    std::uint32_t ordinal = 0;      // valid when by_ordinal
    std::uint16_t hint = 0;
    bool by_ordinal = false;
    bool delayed = false;
    std::uint32_t iat_rva = 0;      // RVA of the IAT slot (where the loader writes the address)
};

struct Export {
    std::string name;               // empty for ordinal-only exports
    std::uint32_t ordinal = 0;
    std::uint32_t rva = 0;
    std::string forwarder;          // "KERNEL32.GetTickCount" when forwarded
};

struct Resource {
    std::string type;               // RT_* name or custom name / "#<id>"
    std::string name;               // name or "#<id>"
    std::uint32_t lang = 0;
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
    std::optional<std::uint64_t> offset;  // file offset when mappable
    std::uint64_t available = 0;    // bytes actually present in the file
    std::optional<double> entropy;  // empty when the analysis byte budget was exhausted
    std::string magic;              // pe | zip | rar | 7z | cab | png | ... | ""
};

struct Debug {
    std::uint32_t type = 0;
    std::string pdb_path;
    std::string guid;               // RSDS GUID as text
    std::uint32_t age = 0;
};

struct PeInfo {
    bool valid = false;             // MZ + PE signature + readable file header
    std::string error;              // why it is not a valid PE (when !valid)
    std::vector<std::string> anomalies;   // stable codes, see pe.cpp

    std::uint32_t e_lfanew = 0;
    std::uint16_t machine = 0;
    std::uint16_t number_of_sections = 0;
    std::uint32_t timestamp = 0;
    std::uint16_t size_of_optional_header = 0;
    std::uint16_t characteristics = 0;
    std::uint16_t magic = 0;        // 0x10B PE32, 0x20B PE32+
    bool is_64 = false;
    bool is_dll = false;
    bool is_driver = false;
    bool is_dotnet = false;
    std::uint32_t entry_point = 0;
    std::uint64_t image_base = 0;
    std::uint32_t section_alignment = 0;
    std::uint32_t file_alignment = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t size_of_headers = 0;
    std::uint32_t checksum = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t dll_characteristics = 0;
    std::uint32_t number_of_rva_and_sizes = 0;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> data_directories;  // (rva, size)

    std::vector<Section> sections;  // sorted by VirtualAddress (loader order)
    std::optional<std::size_t> entry_section;   // index into `sections`

    std::vector<Import> imports;
    std::vector<Export> exports;
    std::string export_name;        // DLL name stored in the export directory
    std::vector<Resource> resources;
    std::map<std::string, std::string> version_info;
    std::string manifest_execution_level;   // asInvoker | highestAvailable | requireAdministrator
    std::uint32_t tls_callbacks = 0;
    std::vector<Debug> debug;
    bool has_rich_header = false;
    std::uint32_t security_offset = 0;      // file offset of the Authenticode certificate table
    std::uint32_t security_size = 0;
    std::optional<std::uint64_t> overlay_offset;
    std::uint64_t overlay_size = 0;
    double overlay_entropy = 0.0;
    std::string overlay_magic;
    bool overlay_is_certificate_only = false;
    std::uint64_t file_size = 0;

    // Derived loader geometry of `sections` (computed by parse(); recomputed if stale).
    struct Geometry {
        std::uint64_t va_adj = 0, ptr_adj = 0, min_rva = 0, max_rva = 0;
        std::uint64_t prefix_max = 0;   // max(max_rva) over sections [0..i], enables O(log n) lookups
    };
    std::vector<Geometry> geometry;
    void compute_geometry();

    // File offset -> containing section index (none for headers/overlay).
    [[nodiscard]] std::optional<std::size_t> section_for_offset(std::uint64_t offset) const;
    // File offset -> RVA (sections and headers).
    [[nodiscard]] std::optional<std::uint32_t> offset_to_rva(std::uint64_t offset) const;
    // RVA -> file offset (pefile semantics, including the "RVA == offset" fallback).
    [[nodiscard]] std::optional<std::uint64_t> rva_to_offset(std::uint32_t rva) const;
    [[nodiscard]] std::optional<std::size_t> section_for_rva(std::uint32_t rva) const;
    // True when a function is imported from any DLL (case-insensitive, exact name).
    [[nodiscard]] bool imports_function(std::string_view name) const;
};

PeInfo parse(ByteView data, const Limits& limits = {});

double shannon_entropy(ByteView data);
// Short tag for known embedded formats ("pe", "zip", ...), "" when unknown.
std::string magic_tag(ByteView data);
std::string machine_name(std::uint16_t machine);

}  // namespace gk::pe
