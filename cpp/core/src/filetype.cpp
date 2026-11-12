#include "gk/filetype.hpp"

#include <algorithm>
#include <array>
#include <vector>

#include "gk/file_view.hpp"

namespace gk {

namespace {

using namespace std::string_view_literals;

constexpr std::array kExecutableExtensions = {
    ".exe"sv, ".dll"sv, ".sys"sv, ".scr"sv, ".com"sv, ".cpl"sv, ".ocx"sv, ".drv"sv, ".efi"sv, ".asi"sv,
    ".xll"sv, ".pyd"sv, ".mui"sv, ".ax"sv,  ".node"sv, ".bin"sv, ".dat"sv, ".tmp"sv};

constexpr std::array kPeTolerated = {".msstyles"sv, ".tlb"sv, ".winmd"sv, ".acm"sv};

struct ScriptExt {
    std::string_view ext;
    std::string_view kind;
};
constexpr std::array kScriptExtensions = {
    ScriptExt{".bat", "bat"}, ScriptExt{".cmd", "bat"},  ScriptExt{".ps1", "ps1"},  ScriptExt{".psm1", "ps1"},
    ScriptExt{".psd1", "ps1"}, ScriptExt{".vbs", "vbs"}, ScriptExt{".vbe", "vbs"},  ScriptExt{".js", "js"},
    ScriptExt{".jse", "js"},   ScriptExt{".wsf", "wsf"}, ScriptExt{".wsh", "wsf"},  ScriptExt{".hta", "hta"},
    ScriptExt{".reg", "reg"},  ScriptExt{".py", "py"},   ScriptExt{".pyw", "py"},   ScriptExt{".sh", "sh"},
    ScriptExt{".ahk", "ahk"},  ScriptExt{".au3", "au3"}, ScriptExt{".inf", "inf"}};

constexpr std::array kArchiveExtensions = {".zip"sv, ".jar"sv, ".apk"sv, ".7z"sv,  ".rar"sv, ".gz"sv, ".tgz"sv,
                                           ".bz2"sv, ".xz"sv,  ".tar"sv, ".cab"sv, ".iso"sv, ".msi"sv, ".zst"sv};

constexpr std::array kGameDataExtensions = {
    ".pak"sv,    ".pck"sv,  ".bik"sv,    ".bk2"sv,   ".usm"sv,    ".wem"sv,   ".bnk"sv,  ".fsb"sv,   ".ogg"sv,
    ".wav"sv,    ".mp3"sv,  ".mp4"sv,    ".webm"sv,  ".avi"sv,    ".dds"sv,   ".png"sv,  ".jpg"sv,   ".jpeg"sv,
    ".tga"sv,    ".ktx"sv,  ".utoc"sv,   ".ucas"sv,  ".forge"sv,  ".vpk"sv,   ".arc"sv,  ".big"sv,   ".assets"sv,
    ".resource"sv, ".ress"sv, ".bundle"sv, ".pkg"sv, ".cpk"sv,    ".obb"sv,   ".gcf"sv,  ".rpf"sv,   ".wad"sv,
    ".bsa"sv,    ".ba2"sv,  ".esm"sv,    ".esp"sv,   ".uasset"sv, ".umap"sv,  ".ttf"sv,  ".otf"sv,   ".fnt"sv,
    ".srt"sv,    ".txt"sv,  ".xml"sv,    ".json"sv,  ".ini"sv,    ".cfg"sv,   ".log"sv,  ".lua"sv,   ".csv"sv,
    ".html"sv,   ".css"sv,  ".svg"sv,    ".mo"sv,    ".po"sv,     ".shader"sv, ".hlsl"sv, ".spv"sv,  ".cache"sv,
    ".sav"sv,    ".save"sv, ".dmp"sv,    ".pdb"sv,   ".bmp"sv,    ".ico"sv};

template <std::size_t N>
bool contains(const std::array<std::string_view, N>& set, std::string_view value) {
    return std::find(set.begin(), set.end(), value) != set.end();
}

const ScriptExt* script_ext(std::string_view ext) {
    for (const auto& s : kScriptExtensions) {
        if (s.ext == ext) return &s;
    }
    return nullptr;
}

TypeInfo make(std::string kind, std::string description, std::string group, bool disguised = false) {
    return TypeInfo{std::move(kind), std::move(description), std::move(group), disguised};
}

bool pe_kind(ByteView h, std::string& kind, std::string& desc) {
    if (h.size() < 0x40 || !h.starts_with("MZ")) return false;
    const std::uint32_t e_lfanew = *h.le<std::uint32_t>(0x3C);
    std::size_t pe_end = 0;
    if (e_lfanew == 0 || !checked_add(e_lfanew, 24, pe_end) || pe_end > h.size()) {
        kind = "msdos";
        desc = "Executável MZ (cabeçalho PE fora da janela de leitura)";
        return true;
    }
    if (!h.equals_at(e_lfanew, std::string_view("PE\0\0", 4))) {
        kind = "msdos";
        desc = "Executável MS-DOS (MZ sem cabeçalho PE)";
        return true;
    }
    const std::uint16_t characteristics = *h.le<std::uint16_t>(e_lfanew + 22);
    const std::size_t opt = static_cast<std::size_t>(e_lfanew) + 24;
    const bool is_dll = (characteristics & 0x2000) != 0;
    int subsystem = -1;
    bool dotnet = false;
    if (auto magic = h.le<std::uint16_t>(opt)) {
        if (*magic == 0x10B || *magic == 0x20B) {
            if (auto sub = h.le<std::uint16_t>(opt + 68)) subsystem = *sub;
            const std::size_t dd_base = opt + (*magic == 0x10B ? 96 : 112);
            const std::size_t clr = dd_base + 14 * 8;
            if (h.has(clr, 8)) dotnet = *h.le<std::uint32_t>(clr) != 0;
        }
    }
    if (subsystem == 1) {
        kind = "pe_sys";
        desc = "Driver do Windows (PE nativo)";
    } else if (dotnet) {
        kind = is_dll ? "pe_dotnet_dll" : "pe_dotnet_exe";
        desc = is_dll ? "Biblioteca .NET" : "Executável .NET";
    } else {
        kind = is_dll ? "pe_dll" : "pe_exe";
        desc = is_dll ? "Biblioteca PE (DLL)" : "Executável PE";
    }
    return true;
}

bool looks_like_text(ByteView h) {
    if (h.empty()) return false;
    const ByteView sample = h.prefix(1024);
    if (sample.starts_with("\xff\xfe") || sample.starts_with("\xfe\xff")) return true;
    std::size_t printable = 0;
    for (std::size_t i = 0; i < sample.size(); ++i) {
        const std::uint8_t b = sample.data()[i];
        if (b == 0) return false;
        if ((b >= 32 && b < 127) || b == 9 || b == 10 || b == 13 || b >= 0x80) ++printable;
    }
    return static_cast<double>(printable) / static_cast<double>(sample.size()) > 0.95;
}

bool is_space(std::uint8_t b) { return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == 0x0B || b == 0x0C; }

std::string lower_bytes(ByteView v) {
    std::string out(reinterpret_cast<const char*>(v.data()), v.size());
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

}  // namespace

std::string lower_ascii(std::string_view text) { return lower_bytes(ByteView(text)); }

std::string extension_of(const std::filesystem::path& path) {
    const auto u8 = path.extension().u8string();
    return lower_ascii(std::string_view(reinterpret_cast<const char*>(u8.data()), u8.size()));
}

bool is_game_data_extension(std::string_view lower_ext) { return contains(kGameDataExtensions, lower_ext); }
bool is_executable_extension(std::string_view lower_ext) { return contains(kExecutableExtensions, lower_ext); }

TypeInfo identify(ByteView h, std::string_view extension, ByteView iso_probe) {
    const std::string ext = lower_ascii(extension);
    {
        std::string kind;
        std::string desc;
        if (pe_kind(h, kind, desc)) {
            const bool disguised = !contains(kExecutableExtensions, ext) && !contains(kPeTolerated, ext);
            return make(kind, desc, "executable", disguised);
        }
    }
    if (h.starts_with("\x7f" "ELF")) {
        return make("elf", "Executável ELF (Linux)", "executable", contains(kGameDataExtensions, ext));
    }
    const bool cafebabe = h.starts_with("\xca\xfe\xba\xbe");
    if ((h.starts_with("\xcf\xfa\xed\xfe") || h.starts_with("\xce\xfa\xed\xfe") || cafebabe) && ext != ".class") {
        return make("macho", "Executável Mach-O", "executable");
    }
    if (h.starts_with(std::string_view("PK\x03\x04", 4)) || h.starts_with(std::string_view("PK\x05\x06", 4))) {
        if (ext == ".jar" || h.find("META-INF/", 0, 512) != ByteView::npos) {
            return make("jar", "Arquivo Java (JAR)", "archive");
        }
        return make("zip", "Arquivo ZIP", "archive");
    }
    if (h.starts_with("Rar!\x1a\x07")) return make("rar", "Arquivo RAR", "archive");
    if (h.starts_with("7z\xbc\xaf\x27\x1c")) return make("7z", "Arquivo 7-Zip", "archive");
    if (h.starts_with("\x1f\x8b")) return make("gzip", "Arquivo GZIP", "archive");
    if (h.starts_with("BZh")) return make("bzip2", "Arquivo BZIP2", "archive");
    if (h.starts_with(std::string_view("\xfd" "7zXZ\x00", 6))) return make("xz", "Arquivo XZ", "archive");
    if (h.starts_with("\x28\xb5\x2f\xfd")) return make("zstd", "Arquivo Zstandard", "archive");
    if (h.starts_with("MSCF")) return make("cab", "Arquivo CAB", "archive");
    if (h.starts_with("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")) {
        if (ext == ".msi" || ext == ".msp" || ext == ".msm") {
            return make("msi", "Pacote Windows Installer (MSI)", "archive");
        }
        return make("ole", "Documento OLE (Office/MSI)", "document");
    }
    if (h.size() > 262 && h.equals_at(257, "ustar")) return make("tar", "Arquivo TAR", "archive");
    if (iso_probe.starts_with("CD001")) return make("iso", "Imagem de disco ISO 9660", "archive");
    if (h.starts_with(std::string_view("L\x00\x00\x00\x01\x14\x02\x00", 8))) {
        return make("lnk", "Atalho do Windows (LNK)", "shortcut");
    }
    if (h.starts_with("%PDF")) return make("pdf", "Documento PDF", "document");
    if (cafebabe && ext == ".class") return make("java_class", "Classe Java", "executable");
    if (h.starts_with("MEI\x0c\x0b\x0a\x0b\x0e")) return make("pyinstaller_archive", "Arquivo PyInstaller", "archive");
    if (const ScriptExt* s = script_ext(ext)) {
        return make(std::string(s->kind), "Script (" + ext + ")", "script");
    }
    if (ext == ".url" && h.find("[InternetShortcut]", 0, 256) != ByteView::npos) {
        return make("url", "Atalho de Internet (.url)", "shortcut");
    }
    if (contains(kArchiveExtensions, ext)) {
        return make("corrupt_archive", "Arquivo " + ext + " com cabeçalho inválido", "archive");
    }
    if (looks_like_text(h)) {
        std::size_t start = 0;
        while (start < h.size() && (h.data()[start] == 0xEF || h.data()[start] == 0xBB || h.data()[start] == 0xBF)) {
            ++start;
        }
        while (start < h.size() && is_space(h.data()[start])) ++start;
        const std::string stripped = lower_bytes(h.clamp(start, h.size()));
        const std::string lowered = lower_bytes(h);
        if (stripped.starts_with("@echo") || lowered.find("\n@echo off") != std::string::npos) {
            return make("bat", "Script batch (sem extensão de script)", "script", ext != ".txt" && !ext.empty());
        }
        if (stripped.starts_with("#!")) return make("sh", "Script com shebang", "script");
        if (stripped.starts_with("windows registry editor") || stripped.starts_with("regedit4")) {
            return make("reg", "Arquivo de registro (.reg)", "script");
        }
        return make("text", "Texto", "text");
    }
    return make("data", "Dados binários", "data");
}

TypeInfo identify_file(const std::filesystem::path& path) {
    const std::vector<std::uint8_t> header = read_range(path, 0, kHeaderSize);
    const std::vector<std::uint8_t> probe = read_range(path, kIsoProbeOffset, kIsoProbeSize);
    return identify(ByteView(header.data(), header.size()), extension_of(path), ByteView(probe.data(), probe.size()));
}

bool group_enabled(const TypeInfo& info, const FileTypeFilter& f) {
    const std::string& kind = info.kind;
    if (kind == "pe_dll" || kind == "pe_dotnet_dll") return f.libraries;
    if (kind == "pe_sys") return f.drivers;
    if (info.group == "executable") return f.executables;
    if (info.group == "script") return f.scripts;
    if (kind == "jar" || kind == "java_class") return f.java;
    if (kind == "msi") return f.installers;
    if (info.group == "archive") return f.archives;
    if (info.group == "shortcut") return f.shortcuts;
    return f.data_sniffing;
}

int priority(const TypeInfo& info, std::string_view file_name) {
    if (info.disguised) return 0;
    if (info.group == "executable") {
        const std::string lname = lower_ascii(file_name);
        for (std::string_view key : {"crack"sv, "keygen"sv, "patch"sv, "loader"sv, "launcher"sv, "setup"sv,
                                     "install"sv, "steam_api"sv}) {
            if (lname.find(key) != std::string::npos) return 1;
        }
        return 2;
    }
    if (info.group == "script" || info.group == "shortcut") return 3;
    if (info.group == "archive") return 4;
    if (info.group == "document" || info.group == "text") return 6;
    return 8;
}

}  // namespace gk
