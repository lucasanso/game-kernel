#include "gk/pe.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <set>

#include "gk/filetype.hpp"
#include "gk/text.hpp"

namespace gk::pe {

namespace {

constexpr std::uint32_t kScnCntCode = 0x00000020;
constexpr std::uint32_t kScnMemExecute = 0x20000000;
constexpr std::uint32_t kScnMemRead = 0x40000000;
constexpr std::uint32_t kScnMemWrite = 0x80000000;

enum Dir : std::size_t {
    kDirExport = 0,
    kDirImport = 1,
    kDirResource = 2,
    kDirSecurity = 4,
    kDirDebug = 6,
    kDirTls = 9,
    kDirDelayImport = 13,
    kDirClr = 14,
};

constexpr std::array<std::string_view, 25> kResourceTypes = {
    "",          "RT_CURSOR",       "RT_BITMAP",       "RT_ICON",       "RT_MENU",      "RT_DIALOG",   "RT_STRING",
    "RT_FONTDIR", "RT_FONT",        "RT_ACCELERATOR",  "RT_RCDATA",     "RT_MESSAGETABLE", "RT_GROUP_CURSOR", "",
    "RT_GROUP_ICON", "",            "RT_VERSION",      "RT_DLGINCLUDE", "",             "RT_PLUGPLAY", "RT_VXD",
    "RT_ANICURSOR", "RT_ANIICON",   "RT_HTML",         "RT_MANIFEST"};

constexpr const char* kKernelModules[] = {"ntoskrnl.exe", "hal.dll", "ndis.sys", "bootvid.dll", "kdcom.dll",
                                          "fltmgr.sys",  "wdfldr.sys", "ksecdd.sys", "cng.sys"};

std::uint64_t adjust_section_alignment(std::uint64_t value, std::uint32_t section_alignment,
                                       std::uint32_t file_alignment) {
    const std::uint64_t alignment = section_alignment < 0x1000 ? file_alignment : section_alignment;
    if (alignment != 0 && value % alignment != 0) return alignment * (value / alignment);
    return value;
}

std::string format_guid(ByteView g) {
    if (g.size() < 16) return {};
    char buf[48];
    std::snprintf(buf, sizeof buf, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", *g.le<std::uint32_t>(0),
                  static_cast<unsigned>(*g.le<std::uint16_t>(4)), static_cast<unsigned>(*g.le<std::uint16_t>(6)),
                  g.data()[8], g.data()[9], g.data()[10], g.data()[11], g.data()[12], g.data()[13], g.data()[14],
                  g.data()[15]);
    return buf;
}

std::string lower(std::string_view s) { return lower_ascii(s); }

class Parser {
public:
    Parser(ByteView data, const Limits& limits, PeInfo& info) : d_(data), lim_(limits), info_(info) {}

    void run();

private:
    void anomaly(const std::string& code) {
        if (std::find(info_.anomalies.begin(), info_.anomalies.end(), code) == info_.anomalies.end()) {
            info_.anomalies.push_back(code);
        }
    }
    [[nodiscard]] std::pair<std::uint32_t, std::uint32_t> dir(std::size_t index) const {
        return index < info_.data_directories.size() ? info_.data_directories[index]
                                                     : std::pair<std::uint32_t, std::uint32_t>{0, 0};
    }
    std::optional<std::uint64_t> off(std::uint64_t rva) const {
        if (rva > 0xFFFFFFFFull) return std::nullopt;
        return info_.rva_to_offset(static_cast<std::uint32_t>(rva));
    }
    std::optional<std::uint32_t> u32_at_rva(std::uint64_t rva) const {
        auto o = off(rva);
        return o ? d_.le<std::uint32_t>(static_cast<std::size_t>(*o)) : std::nullopt;
    }
    std::optional<std::uint64_t> thunk_at_rva(std::uint64_t rva) const {
        auto o = off(rva);
        if (!o) return std::nullopt;
        if (info_.is_64) return d_.le<std::uint64_t>(static_cast<std::size_t>(*o));
        auto v = d_.le<std::uint32_t>(static_cast<std::size_t>(*o));
        return v ? std::optional<std::uint64_t>(*v) : std::nullopt;
    }
    std::string string_at_rva(std::uint64_t rva, std::size_t max_len) const {
        auto o = off(rva);
        return o ? text::c_string(d_, static_cast<std::size_t>(*o), max_len) : std::string();
    }

    bool headers();
    void sections();
    void imports();
    void delay_imports();
    void exports();
    void resources();
    void resource_dir(std::uint64_t base, std::uint64_t rel, std::size_t depth, std::vector<std::string>& path,
                      std::vector<std::uint32_t>& ids, std::set<std::uint64_t>& visited);
    void version_info(const Resource& r);
    void manifest(const Resource& r);
    void tls();
    void debug();
    void overlay();
    void import_thunks(const std::string& dll, std::uint64_t lookup_rva, std::uint64_t iat_rva, bool delayed);

    ByteView d_;
    const Limits& lim_;
    PeInfo& info_;
    std::size_t imports_total_ = 0;
    std::uint64_t resource_budget_used_ = 0;
    // Identical data entries (rva, size) are analysed once: hostile files repeat them thousands of times.
    std::map<std::pair<std::uint32_t, std::uint32_t>, std::pair<std::optional<double>, std::string>> resource_cache_;
};

bool Parser::headers() {
    info_.file_size = d_.size();
    if (d_.size() < 0x40 || !d_.starts_with("MZ")) {
        info_.error = "sem cabeçalho MZ";
        return false;
    }
    info_.e_lfanew = *d_.le<std::uint32_t>(0x3C);
    const std::size_t nt = info_.e_lfanew;
    if (!d_.has(nt, 24) || !d_.equals_at(nt, std::string_view("PE\0\0", 4))) {
        info_.error = "assinatura PE ausente ou fora do arquivo";
        return false;
    }
    info_.machine = *d_.le<std::uint16_t>(nt + 4);
    info_.number_of_sections = *d_.le<std::uint16_t>(nt + 6);
    info_.timestamp = *d_.le<std::uint32_t>(nt + 8);
    info_.size_of_optional_header = *d_.le<std::uint16_t>(nt + 20);
    info_.characteristics = *d_.le<std::uint16_t>(nt + 22);
    info_.is_dll = (info_.characteristics & 0x2000) != 0;

    const std::size_t opt = nt + 24;
    auto magic = d_.le<std::uint16_t>(opt);
    if (!magic || (*magic != 0x10B && *magic != 0x20B)) {
        info_.error = "cabeçalho opcional ausente ou com tipo desconhecido";
        return false;
    }
    info_.magic = *magic;
    info_.is_64 = *magic == 0x20B;
    auto u32 = [&](std::size_t o) { return d_.le<std::uint32_t>(opt + o).value_or(0); };
    auto u16 = [&](std::size_t o) { return d_.le<std::uint16_t>(opt + o).value_or(0); };
    const std::size_t standard_size = info_.is_64 ? 112 : 96;
    if (!d_.has(opt, standard_size)) anomaly("optional_header_truncated");
    info_.entry_point = u32(16);
    info_.image_base = info_.is_64 ? d_.le<std::uint64_t>(opt + 24).value_or(0) : u32(28);
    info_.section_alignment = u32(32);
    info_.file_alignment = u32(36);
    info_.size_of_image = u32(56);
    info_.size_of_headers = u32(60);
    info_.checksum = u32(64);
    info_.subsystem = u16(68);
    info_.dll_characteristics = u16(70);
    info_.number_of_rva_and_sizes = u32(info_.is_64 ? 108 : 92);
    const std::size_t dd = opt + standard_size;
    const std::size_t count = std::min<std::size_t>(info_.number_of_rva_and_sizes, 16);
    for (std::size_t i = 0; i < count; ++i) {
        auto rva = d_.le<std::uint32_t>(dd + i * 8);
        auto size = d_.le<std::uint32_t>(dd + i * 8 + 4);
        if (!rva || !size) {
            anomaly("data_directories_truncated");
            break;
        }
        info_.data_directories.emplace_back(*rva, *size);
    }
    if (info_.number_of_rva_and_sizes > 16) anomaly("data_directories_count_invalid");
    info_.is_dotnet = dir(kDirClr).first != 0;
    info_.security_offset = dir(kDirSecurity).first;
    info_.security_size = dir(kDirSecurity).second;
    // Rich header: compiler metadata between the DOS stub and the PE header.
    if (info_.e_lfanew > 0x80) info_.has_rich_header = d_.find("Rich", 0x80, info_.e_lfanew) != ByteView::npos;
    return true;
}

}  // namespace

namespace {
std::vector<PeInfo::Geometry> geometry_of(const PeInfo& info) {
    const auto& sections = info.sections;
    std::vector<PeInfo::Geometry> geometry(sections.size());
    const std::uint32_t section_alignment = info.section_alignment;
    const std::uint32_t file_alignment = info.file_alignment;
    const std::uint64_t file_size = info.file_size;
    for (std::size_t i = 0; i < sections.size(); ++i) {
        const Section& s = sections[i];
        PeInfo::Geometry& out = geometry[i];
        out.va_adj = adjust_section_alignment(s.virtual_address, section_alignment, file_alignment);
        std::uint64_t ptr = s.raw_offset & ~0x1FFull;
        if (section_alignment < 0x1000 && s.raw_offset == s.virtual_address) ptr = s.virtual_address;
        out.ptr_adj = ptr;
        std::uint64_t size = 0;
        const auto remaining = static_cast<std::int64_t>(file_size) - static_cast<std::int64_t>(ptr);
        if (remaining < static_cast<std::int64_t>(s.raw_size)) {
            size = s.virtual_size;
        } else {
            size = std::max<std::uint64_t>(s.raw_size, s.virtual_size);
        }
        if (i + 1 < sections.size()) {
            const std::uint64_t next_va = sections[i + 1].virtual_address;
            if (next_va > s.virtual_address && out.va_adj + size > next_va) size = next_va - out.va_adj;
        }
        out.min_rva = out.va_adj;
        out.max_rva = out.va_adj + size;
        out.prefix_max = i == 0 ? out.max_rva : std::max(geometry[i - 1].prefix_max, out.max_rva);
    }
    return geometry;
}

// Uses the cached geometry when fresh; otherwise computes it into `scratch` (no mutation of `info`).
const std::vector<PeInfo::Geometry>& geo(const PeInfo& info, std::vector<PeInfo::Geometry>& scratch) {
    if (info.geometry.size() == info.sections.size()) return info.geometry;
    scratch = geometry_of(info);
    return scratch;
}
}  // namespace

void PeInfo::compute_geometry() { geometry = geometry_of(*this); }

namespace {
// First section (in loader order) whose [min_rva, max_rva) contains `rva`, in O(log n):
// min_rva is non-decreasing, so candidates are [0, k] with k = last index having min_rva <= rva;
// the first i with prefix_max > rva is the first section whose range extends past `rva`.
std::optional<std::size_t> find_rva(const std::vector<PeInfo::Geometry>& g, std::uint64_t rva) {
    auto upper = std::upper_bound(g.begin(), g.end(), rva,
                                  [](std::uint64_t value, const PeInfo::Geometry& x) { return value < x.min_rva; });
    if (upper == g.begin()) return std::nullopt;
    const std::size_t k = static_cast<std::size_t>(upper - g.begin()) - 1;
    auto first = std::upper_bound(g.begin(), g.begin() + static_cast<std::ptrdiff_t>(k) + 1, rva,
                                  [](std::uint64_t value, const PeInfo::Geometry& x) { return value < x.prefix_max; });
    if (first == g.begin() + static_cast<std::ptrdiff_t>(k) + 1) return std::nullopt;
    return static_cast<std::size_t>(first - g.begin());
}
}  // namespace

std::optional<std::size_t> PeInfo::section_for_rva(std::uint32_t rva) const {
    std::vector<Geometry> scratch;
    return find_rva(geo(*this, scratch), rva);
}

std::optional<std::uint64_t> PeInfo::rva_to_offset(std::uint32_t rva) const {
    std::vector<Geometry> scratch;
    const auto& g = geo(*this, scratch);
    if (auto i = find_rva(g, rva)) return rva - g[*i].va_adj + g[*i].ptr_adj;
    if (rva < file_size) return rva;
    return std::nullopt;
}

std::optional<std::size_t> PeInfo::section_for_offset(std::uint64_t offset) const {
    std::vector<Geometry> scratch;
    const auto& g = geo(*this, scratch);
    for (std::size_t i = 0; i < g.size(); ++i) {
        if (g[i].ptr_adj <= offset && offset < g[i].ptr_adj + sections[i].raw_size) return i;
    }
    return std::nullopt;
}

std::optional<std::uint32_t> PeInfo::offset_to_rva(std::uint64_t offset) const {
    std::vector<Geometry> scratch;
    const auto& g = geo(*this, scratch);
    for (std::size_t i = 0; i < g.size(); ++i) {
        if (g[i].ptr_adj <= offset && offset < g[i].ptr_adj + sections[i].raw_size) {
            const std::uint64_t rva = offset - g[i].ptr_adj + g[i].va_adj;
            if (rva <= 0xFFFFFFFFull) return static_cast<std::uint32_t>(rva);
            return std::nullopt;
        }
    }
    // Not inside any section: offsets before the lowest section start are header bytes mapped 1:1.
    std::uint64_t lowest = 0xFFFFFFFFull;
    for (const auto& geom : g) lowest = std::min(lowest, geom.va_adj);
    if (g.empty() || offset < lowest) {
        if (offset <= 0xFFFFFFFFull) return static_cast<std::uint32_t>(offset);
    }
    return std::nullopt;
}

bool PeInfo::imports_function(std::string_view name) const {
    const std::string wanted = lower_ascii(name);
    return std::any_of(imports.begin(), imports.end(), [&](const Import& i) { return lower_ascii(i.name) == wanted; });
}

namespace {

void Parser::sections() {
    const std::size_t table = static_cast<std::size_t>(info_.e_lfanew) + 24 + info_.size_of_optional_header;
    if (info_.number_of_sections > 96) anomaly("sections_over_96");
    if (info_.number_of_sections == 0) anomaly("no_sections");
    std::vector<Section> parsed;
    for (std::size_t i = 0; i < info_.number_of_sections; ++i) {
        if (i >= lim_.max_sections) {
            anomaly("too_many_sections");
            break;
        }
        auto hdr = d_.sub(table + 40 * i, 40);
        if (!hdr) {
            anomaly("section_table_truncated");
            break;
        }
        if (std::all_of(hdr->data(), hdr->data() + 40, [](std::uint8_t b) { return b == 0; })) {
            anomaly("null_section_header");
            break;
        }
        Section s;
        std::string raw(reinterpret_cast<const char*>(hdr->data()), 8);
        raw = raw.substr(0, raw.find('\0'));
        s.name = text::escape_bytes(raw);
        if (s.name != raw) anomaly("section_name_nonprintable");
        s.virtual_size = *hdr->le<std::uint32_t>(8);
        s.virtual_address = *hdr->le<std::uint32_t>(12);
        s.raw_size = *hdr->le<std::uint32_t>(16);
        s.raw_offset = *hdr->le<std::uint32_t>(20);
        s.characteristics = *hdr->le<std::uint32_t>(36);
        s.executable = (s.characteristics & kScnMemExecute) != 0;
        s.writable = (s.characteristics & kScnMemWrite) != 0;
        s.readable = (s.characteristics & kScnMemRead) != 0;
        s.contains_code = (s.characteristics & kScnCntCode) != 0;
        s.header_index = i;
        int errors = 0;
        if (static_cast<std::uint64_t>(s.raw_size) + s.raw_offset > d_.size()) {
            ++errors;
            s.raw_beyond_eof = true;
            anomaly("section_raw_beyond_eof");
        }
        if ((s.raw_offset & ~0x1FFull) > d_.size()) ++errors;
        if (s.virtual_size > 0x10000000) {
            ++errors;
            anomaly("section_virtual_size_huge");
        }
        if (adjust_section_alignment(s.virtual_address, info_.section_alignment, info_.file_alignment) > 0x10000000) {
            ++errors;
            anomaly("section_virtual_address_huge");
        }
        if (info_.file_alignment != 0 && s.raw_offset % info_.file_alignment != 0) {
            ++errors;
            anomaly("section_raw_unaligned");
        }
        if (errors >= 3) {
            anomaly("section_table_abort");
            break;
        }
        if (s.writable && s.executable && !(raw == "PAGE" && info_.subsystem == 1)) anomaly("section_write_execute");
        parsed.push_back(std::move(s));
    }
    std::stable_sort(parsed.begin(), parsed.end(),
                     [](const Section& a, const Section& b) { return a.virtual_address < b.virtual_address; });
    info_.sections = std::move(parsed);
    info_.compute_geometry();

    const auto& g = info_.geometry;
    for (std::size_t i = 0; i < info_.sections.size(); ++i) {
        Section& s = info_.sections[i];
        const ByteView raw = d_.clamp(static_cast<std::size_t>(std::min<std::uint64_t>(g[i].ptr_adj, d_.size())),
                                      s.raw_size);
        s.data_size = raw.size();
        s.entropy = shannon_entropy(raw);
    }

    info_.entry_section = info_.section_for_rva(info_.entry_point);
    if (info_.entry_point == 0) {
        if (!info_.is_dll) anomaly("entrypoint_zero");
    } else if (!info_.entry_section) {
        anomaly("entrypoint_outside_sections");
    } else {
        const Section& ep = info_.sections[*info_.entry_section];
        if (!ep.executable && !ep.contains_code) anomaly("entrypoint_in_non_executable_section");
        if (*info_.entry_section + 1 == info_.sections.size() && info_.sections.size() > 1) {
            anomaly("entrypoint_in_last_section");
        }
        if (ep.writable) anomaly("entrypoint_in_writable_section");
    }
}

void Parser::import_thunks(const std::string& dll, std::uint64_t lookup_rva, std::uint64_t iat_rva, bool delayed) {
    const std::uint64_t step = info_.is_64 ? 8 : 4;
    const std::uint64_t ordinal_flag = info_.is_64 ? 0x8000000000000000ull : 0x80000000ull;
    for (std::size_t i = 0; i < lim_.max_imports_per_dll; ++i) {
        if (imports_total_ >= lim_.max_imports_total) {
            anomaly("imports_limit_reached");
            return;
        }
        auto value = thunk_at_rva(lookup_rva + i * step);
        if (!value) {
            anomaly("import_thunks_unreadable");
            return;
        }
        if (*value == 0) return;
        Import imp;
        imp.dll = dll;
        imp.delayed = delayed;
        imp.iat_rva = static_cast<std::uint32_t>((iat_rva + i * step) & 0xFFFFFFFFull);
        if (*value & ordinal_flag) {
            imp.by_ordinal = true;
            imp.ordinal = static_cast<std::uint32_t>(*value & 0xFFFF);
        } else {
            const std::uint64_t hint_rva = *value & 0x7FFFFFFFull;
            auto o = off(hint_rva);
            if (!o) {
                anomaly("import_name_unmapped");
                continue;
            }
            imp.hint = d_.le<std::uint16_t>(static_cast<std::size_t>(*o)).value_or(0);
            imp.name = text::c_string(d_, static_cast<std::size_t>(*o) + 2, lim_.max_name_length);
        }
        info_.imports.push_back(std::move(imp));
        ++imports_total_;
    }
    anomaly("imports_per_dll_limit_reached");
}

void Parser::imports() {
    const std::uint32_t rva = dir(kDirImport).first;
    if (rva == 0) return;
    auto base = off(rva);
    if (!base) {
        anomaly("import_directory_unmapped");
        return;
    }
    for (std::size_t n = 0; n < lim_.max_import_descriptors; ++n) {
        auto desc = d_.sub(static_cast<std::size_t>(*base) + 20 * n, 20);
        if (!desc) {
            anomaly("import_directory_truncated");
            return;
        }
        if (std::all_of(desc->data(), desc->data() + 20, [](std::uint8_t b) { return b == 0; })) return;
        const std::uint32_t oft = *desc->le<std::uint32_t>(0);
        const std::uint32_t name_rva = *desc->le<std::uint32_t>(12);
        const std::uint32_t ft = *desc->le<std::uint32_t>(16);
        const std::string dll = string_at_rva(name_rva, lim_.max_name_length);
        if (dll.empty()) anomaly("import_dll_name_invalid");
        import_thunks(dll, oft != 0 ? oft : ft, ft, false);
    }
    anomaly("import_descriptors_limit_reached");
}

void Parser::delay_imports() {
    const std::uint32_t rva = dir(kDirDelayImport).first;
    if (rva == 0) return;
    auto base = off(rva);
    if (!base) {
        anomaly("delay_import_directory_unmapped");
        return;
    }
    for (std::size_t n = 0; n < lim_.max_import_descriptors; ++n) {
        auto desc = d_.sub(static_cast<std::size_t>(*base) + 32 * n, 32);
        if (!desc) {
            anomaly("delay_import_directory_truncated");
            return;
        }
        if (std::all_of(desc->data(), desc->data() + 32, [](std::uint8_t b) { return b == 0; })) return;
        const std::uint32_t attrs = *desc->le<std::uint32_t>(0);
        std::uint64_t name = *desc->le<std::uint32_t>(4);
        std::uint64_t iat = *desc->le<std::uint32_t>(12);
        std::uint64_t names = *desc->le<std::uint32_t>(16);
        if ((attrs & 1) == 0) {  // legacy descriptor with virtual addresses
            const std::uint64_t ib = info_.image_base & 0xFFFFFFFFull;
            name = name >= ib ? name - ib : 0;
            iat = iat >= ib ? iat - ib : 0;
            names = names >= ib ? names - ib : 0;
        }
        const std::string dll = string_at_rva(name, lim_.max_name_length);
        import_thunks(dll, names, iat, true);
    }
}

void Parser::exports() {
    const auto [rva, size] = dir(kDirExport);
    if (rva == 0) return;
    auto base = off(rva);
    auto hdr = base ? d_.sub(static_cast<std::size_t>(*base), 40) : std::nullopt;
    if (!hdr) {
        anomaly("export_directory_invalid");
        return;
    }
    info_.export_name = string_at_rva(*hdr->le<std::uint32_t>(12), lim_.max_name_length);
    const std::uint32_t ordinal_base = *hdr->le<std::uint32_t>(16);
    std::uint64_t functions = *hdr->le<std::uint32_t>(20);
    std::uint64_t names = *hdr->le<std::uint32_t>(24);
    const std::uint32_t aof = *hdr->le<std::uint32_t>(28);
    const std::uint32_t aon = *hdr->le<std::uint32_t>(32);
    const std::uint32_t aoo = *hdr->le<std::uint32_t>(36);
    if (functions > lim_.max_exports || names > lim_.max_exports) {
        anomaly("exports_limit_reached");
        functions = std::min<std::uint64_t>(functions, lim_.max_exports);
        names = std::min<std::uint64_t>(names, lim_.max_exports);
    }
    std::vector<std::uint32_t> addresses;
    addresses.reserve(static_cast<std::size_t>(functions));
    for (std::uint64_t i = 0; i < functions; ++i) {
        auto a = u32_at_rva(static_cast<std::uint64_t>(aof) + 4 * i);
        if (!a) {
            anomaly("export_functions_truncated");
            break;
        }
        addresses.push_back(*a);
    }
    auto forwarder = [&](std::uint32_t func_rva) -> std::string {
        if (func_rva >= rva && static_cast<std::uint64_t>(func_rva) < static_cast<std::uint64_t>(rva) + size) {
            return string_at_rva(func_rva, lim_.max_name_length);
        }
        return {};
    };
    std::vector<bool> named(addresses.size(), false);
    for (std::uint64_t i = 0; i < names; ++i) {
        auto name_rva = u32_at_rva(static_cast<std::uint64_t>(aon) + 4 * i);
        auto ord_off = off(static_cast<std::uint64_t>(aoo) + 2 * i);
        auto ord = ord_off ? d_.le<std::uint16_t>(static_cast<std::size_t>(*ord_off)) : std::nullopt;
        if (!name_rva || !ord) {
            anomaly("export_names_truncated");
            break;
        }
        if (*ord >= addresses.size()) {
            anomaly("export_ordinal_out_of_range");
            continue;
        }
        Export e;
        e.name = string_at_rva(*name_rva, lim_.max_name_length);
        e.ordinal = ordinal_base + *ord;
        e.rva = addresses[*ord];
        e.forwarder = forwarder(e.rva);
        named[*ord] = true;
        info_.exports.push_back(std::move(e));
    }
    for (std::size_t i = 0; i < addresses.size(); ++i) {
        if (named[i] || addresses[i] == 0) continue;
        Export e;
        e.ordinal = ordinal_base + static_cast<std::uint32_t>(i);
        e.rva = addresses[i];
        e.forwarder = forwarder(e.rva);
        info_.exports.push_back(std::move(e));
    }
}

void Parser::resources() {
    const std::uint32_t rva = dir(kDirResource).first;
    if (rva == 0) return;
    auto base = off(rva);
    if (!base) {
        anomaly("resource_directory_unmapped");
        return;
    }
    std::vector<std::string> path;
    std::vector<std::uint32_t> ids;
    std::set<std::uint64_t> visited;
    resource_dir(*base, 0, 0, path, ids, visited);
    // Only the first RT_VERSION / RT_MANIFEST is interpreted (that is what Windows uses); attempting every
    // entry would let a hostile file multiply the work.
    bool version_done = false;
    bool manifest_done = false;
    for (const Resource& r : info_.resources) {
        if (!version_done && r.type == "RT_VERSION") {
            version_info(r);
            version_done = true;
        }
        if (!manifest_done && r.type == "RT_MANIFEST") {
            manifest(r);
            manifest_done = true;
        }
        if (version_done && manifest_done) break;
    }
}

void Parser::resource_dir(std::uint64_t base, std::uint64_t rel, std::size_t depth, std::vector<std::string>& path,
                          std::vector<std::uint32_t>& ids, std::set<std::uint64_t>& visited) {
    if (depth >= lim_.max_resource_depth) {
        anomaly("resource_depth_exceeded");
        return;
    }
    if (!visited.insert(rel).second) {
        anomaly("resource_loop");
        return;
    }
    auto hdr = d_.sub(static_cast<std::size_t>(base + rel), 16);
    if (!hdr) {
        anomaly("resource_directory_truncated");
        return;
    }
    const std::size_t count = static_cast<std::size_t>(*hdr->le<std::uint16_t>(12)) + *hdr->le<std::uint16_t>(14);
    for (std::size_t i = 0; i < count; ++i) {
        if (info_.resources.size() >= lim_.max_resources) {
            anomaly("resources_limit_reached");
            return;
        }
        auto entry = d_.sub(static_cast<std::size_t>(base + rel + 16 + 8 * i), 8);
        if (!entry) {
            anomaly("resource_directory_truncated");
            return;
        }
        const std::uint32_t name_field = *entry->le<std::uint32_t>(0);
        const std::uint32_t data_field = *entry->le<std::uint32_t>(4);
        std::string label;
        std::uint32_t id = 0;
        if (name_field & 0x80000000u) {
            const std::uint64_t name_off = base + (name_field & 0x7FFFFFFFu);
            auto length = d_.le<std::uint16_t>(static_cast<std::size_t>(name_off));
            if (length) {
                label = text::utf16le_to_utf8(d_.clamp(static_cast<std::size_t>(name_off) + 2, *length * 2u), *length);
            }
        } else {
            id = name_field & 0xFFFF;
            if (depth == 0 && id < kResourceTypes.size() && !kResourceTypes[id].empty()) {
                label = std::string(kResourceTypes[id]);
            } else {
                label = "#" + std::to_string(id);
            }
        }
        path.push_back(label);
        ids.push_back(id);
        if (data_field & 0x80000000u) {
            resource_dir(base, data_field & 0x7FFFFFFFu, depth + 1, path, ids, visited);
        } else {
            auto data_entry = d_.sub(static_cast<std::size_t>(base + data_field), 16);
            if (!data_entry) {
                anomaly("resource_entry_truncated");
            } else {
                Resource r;
                r.type = path.empty() ? std::string() : path[0];
                r.name = path.size() > 1 ? path[1] : std::string();
                r.lang = ids.size() > 2 ? ids[2] : 0;
                r.rva = *data_entry->le<std::uint32_t>(0);
                r.size = *data_entry->le<std::uint32_t>(4);
                r.offset = info_.rva_to_offset(r.rva);
                if (r.offset && *r.offset < d_.size()) {
                    const ByteView bytes = d_.clamp(static_cast<std::size_t>(*r.offset), r.size);
                    r.available = bytes.size();
                    const auto key = std::make_pair(r.rva, r.size);
                    auto cached = resource_cache_.find(key);
                    if (cached != resource_cache_.end()) {
                        r.entropy = cached->second.first;
                        r.magic = cached->second.second;
                    } else {
                        if (resource_budget_used_ + bytes.size() <= lim_.resource_analysis_budget) {
                            resource_budget_used_ += bytes.size();
                            r.entropy = shannon_entropy(bytes);
                        } else {
                            anomaly("resource_analysis_budget_exhausted");
                        }
                        r.magic = magic_tag(bytes);
                        resource_cache_.emplace(key, std::make_pair(r.entropy, r.magic));
                    }
                } else {
                    anomaly("resource_data_unmapped");
                }
                info_.resources.push_back(std::move(r));
            }
        }
        path.pop_back();
        ids.pop_back();
    }
}

// VS_VERSIONINFO: generic block = wLength, wValueLength, wType, szKey (UTF-16, NUL), pad to 4,
// value, pad to 4, children. Offsets are relative to the resource start (32-bit aligned).
void Parser::version_info(const Resource& r) {
    if (!r.offset) return;
    const ByteView res = d_.clamp(static_cast<std::size_t>(*r.offset), std::min<std::size_t>(r.size, lim_.max_version_bytes));
    struct Block {
        std::size_t start, end, value_start, children_start;
        std::uint16_t value_length, type;
        std::string key;
    };
    auto align4 = [](std::size_t v) { return (v + 3) & ~static_cast<std::size_t>(3); };
    auto block = [&](std::size_t start, std::size_t limit) -> std::optional<Block> {
        auto length = res.le<std::uint16_t>(start);
        auto vlen = res.le<std::uint16_t>(start + 2);
        auto type = res.le<std::uint16_t>(start + 4);
        if (!length || !vlen || !type || *length < 6) return std::nullopt;
        Block b{start, std::min(start + *length, limit), 0, 0, *vlen, *type, {}};
        std::size_t consumed = 0;
        b.key = text::utf16le_to_utf8(res.clamp(start + 6, b.end > start + 6 ? b.end - start - 6 : 0), 256, &consumed);
        b.value_start = align4(start + 6 + consumed);
        const std::size_t value_bytes = b.type == 1 ? static_cast<std::size_t>(b.value_length) * 2 : b.value_length;
        b.children_start = align4(b.value_start + value_bytes);
        return b;
    };
    auto root = block(0, res.size());
    if (!root || root->key != "VS_VERSION_INFO") {
        anomaly("version_info_invalid");
        return;
    }
    std::size_t pos = root->children_start;
    int guard = 0;
    while (pos < root->end && guard++ < 64) {
        auto child = block(pos, root->end);
        if (!child) break;
        if (child->key == "StringFileInfo") {
            std::size_t tpos = child->children_start;
            int tguard = 0;
            while (tpos < child->end && tguard++ < 64) {
                auto table = block(tpos, child->end);
                if (!table) break;
                std::size_t spos = table->children_start;
                int sguard = 0;
                while (spos < table->end && sguard++ < 512) {
                    auto str = block(spos, table->end);
                    if (!str) break;
                    std::string value = text::utf16le_to_utf8(
                        res.clamp(str->value_start, str->end > str->value_start ? str->end - str->value_start : 0),
                        str->value_length);
                    info_.version_info.emplace(str->key, std::move(value));
                    spos = align4(str->end);
                    if (str->end <= str->start) break;
                }
                tpos = align4(table->end);
                if (table->end <= table->start) break;
            }
        }
        pos = align4(child->end);
        if (child->end <= child->start) break;
    }
}

void Parser::manifest(const Resource& r) {
    if (!r.offset) return;
    const ByteView m = d_.clamp(static_cast<std::size_t>(*r.offset), std::min<std::size_t>(r.size, lim_.max_manifest_bytes));
    const std::string_view xml(reinterpret_cast<const char*>(m.data()), m.size());
    const auto tag = xml.find("requestedExecutionLevel");
    if (tag == std::string::npos) return;
    const auto attr = xml.find("level", tag + 23);
    if (attr == std::string::npos) return;
    const auto quote = xml.find_first_of("\"'", attr);
    if (quote == std::string::npos) return;
    const auto end = xml.find(xml[quote], quote + 1);
    if (end == std::string::npos || end - quote > 64) return;
    info_.manifest_execution_level = std::string(xml.substr(quote + 1, end - quote - 1));
}

void Parser::tls() {
    const std::uint32_t rva = dir(kDirTls).first;
    if (rva == 0) return;
    auto base = off(rva);
    if (!base) {
        anomaly("tls_directory_unmapped");
        return;
    }
    const std::uint64_t callbacks_va = info_.is_64
        ? d_.le<std::uint64_t>(static_cast<std::size_t>(*base) + 24).value_or(0)
        : d_.le<std::uint32_t>(static_cast<std::size_t>(*base) + 12).value_or(0);
    if (callbacks_va == 0) return;
    if (callbacks_va < info_.image_base) {
        anomaly("tls_callbacks_invalid");
        return;
    }
    const std::uint64_t step = info_.is_64 ? 8 : 4;
    for (std::size_t i = 0; i < lim_.max_tls_callbacks; ++i) {
        auto value = thunk_at_rva(callbacks_va - info_.image_base + i * step);
        if (!value || *value == 0) return;
        ++info_.tls_callbacks;
    }
    anomaly("tls_callbacks_limit_reached");
}

void Parser::debug() {
    const auto [rva, size] = dir(kDirDebug);
    if (rva == 0) return;
    auto base = off(rva);
    if (!base) return;
    const std::size_t count = std::min<std::size_t>(size / 28, lim_.max_debug_entries);
    for (std::size_t i = 0; i < count; ++i) {
        auto e = d_.sub(static_cast<std::size_t>(*base) + 28 * i, 28);
        if (!e) break;
        Debug dbg;
        dbg.type = *e->le<std::uint32_t>(12);
        const std::uint32_t data_size = *e->le<std::uint32_t>(16);
        const std::uint32_t raw = *e->le<std::uint32_t>(24);
        if (dbg.type == 2 && data_size >= 24) {
            const ByteView cv = d_.clamp(raw, data_size);
            if (cv.starts_with("RSDS") && cv.size() >= 24) {
                dbg.guid = format_guid(cv.clamp(4, 16));
                dbg.age = *cv.le<std::uint32_t>(20);
                dbg.pdb_path = text::c_string(cv, 24, 1024);
            } else if (cv.starts_with("NB10") && cv.size() >= 16) {
                dbg.age = *cv.le<std::uint32_t>(12);
                dbg.pdb_path = text::c_string(cv, 16, 1024);
            }
        }
        info_.debug.push_back(std::move(dbg));
    }
}

void Parser::overlay() {
    std::uint64_t largest = 0;
    auto update = [&](std::uint64_t offset, std::uint64_t size) {
        const std::uint64_t end = offset + size;
        if (largest < end && end <= d_.size()) largest = end;
    };
    update(static_cast<std::uint64_t>(info_.e_lfanew) + 24, info_.size_of_optional_header);
    for (const Section& s : info_.sections) update(s.raw_offset, s.raw_size);
    for (std::size_t i = 0; i < info_.data_directories.size(); ++i) {
        if (i == kDirSecurity) continue;
        auto o = info_.rva_to_offset(info_.data_directories[i].first);
        if (o) update(*o, info_.data_directories[i].second);
    }
    if (d_.size() > largest) {
        info_.overlay_offset = largest;
        info_.overlay_size = d_.size() - largest;
        const ByteView ov = d_.clamp(static_cast<std::size_t>(largest), static_cast<std::size_t>(info_.overlay_size));
        info_.overlay_entropy = shannon_entropy(ov.prefix(256u << 20));
        info_.overlay_magic = magic_tag(ov);
        info_.overlay_is_certificate_only =
            info_.security_offset != 0 && info_.security_offset == largest &&
            static_cast<std::uint64_t>(info_.security_offset) + info_.security_size + 8 >= d_.size();
    }
}

void Parser::run() {
    if (!headers()) return;
    info_.valid = true;
    sections();
    imports();
    delay_imports();
    exports();
    resources();
    tls();
    debug();
    overlay();
    if (info_.subsystem == 1) {
        info_.is_driver = true;
    } else {
        for (const Import& imp : info_.imports) {
            const std::string dll = lower(imp.dll);
            for (const char* k : kKernelModules) {
                if (dll == k) info_.is_driver = true;
            }
        }
    }
}

}  // namespace

PeInfo parse(ByteView data, const Limits& limits) {
    PeInfo info;
    Parser(data, limits, info).run();
    return info;
}

double shannon_entropy(ByteView data) {
    if (data.empty()) return 0.0;
    std::array<std::uint64_t, 256> counts{};
    const std::uint8_t* p = data.data();
    for (std::size_t i = 0; i < data.size(); ++i) ++counts[p[i]];
    double entropy = 0.0;
    const double total = static_cast<double>(data.size());
    for (std::uint64_t c : counts) {
        if (c == 0) continue;
        const double prob = static_cast<double>(c) / total;
        entropy -= prob * std::log2(prob);
    }
    return entropy;
}

std::string magic_tag(ByteView d) {
    if (d.starts_with("MZ")) {
        auto lfanew = d.le<std::uint32_t>(0x3C);
        if (lfanew && d.equals_at(*lfanew, std::string_view("PE\0\0", 4))) return "pe";
        return "mz";
    }
    if (d.starts_with(std::string_view("PK\x03\x04", 4))) return "zip";
    if (d.starts_with("Rar!\x1a\x07")) return "rar";
    if (d.starts_with("7z\xbc\xaf\x27\x1c")) return "7z";
    if (d.starts_with("MSCF")) return "cab";
    if (d.starts_with("\x1f\x8b")) return "gzip";
    if (d.starts_with(std::string_view("\xfd" "7zXZ\x00", 6))) return "xz";
    if (d.starts_with("BZh")) return "bzip2";
    if (d.starts_with("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")) return "ole";
    if (d.starts_with("\x89PNG")) return "png";
    if (d.starts_with("\xff\xd8\xff")) return "jpeg";
    if (d.starts_with("GIF8")) return "gif";
    if (d.starts_with("%PDF")) return "pdf";
    if (d.starts_with("\x7f" "ELF")) return "elf";
    if (d.starts_with("\x1bLua")) return "lua";
    if (d.equals_at(4, "\xef\xbe\xad\xdeNullsoftInst")) return "nsis";
    if (d.starts_with("zlb\x1a") || d.starts_with("Inno Setup")) return "inno";
    if (d.starts_with(std::string_view("\x00\x00\x01\x00", 4))) return "ico";
    return {};
}

std::string machine_name(std::uint16_t machine) {
    switch (machine) {
        case 0x014C: return "x86";
        case 0x8664: return "x64";
        case 0xAA64: return "arm64";
        case 0x01C4: return "arm";
        case 0x0200: return "ia64";
        default: {
            char buf[8];
            std::snprintf(buf, sizeof buf, "0x%04X", machine);
            return buf;
        }
    }
}

}  // namespace gk::pe
