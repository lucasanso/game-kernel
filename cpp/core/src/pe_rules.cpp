// Structural evidence for PE files. Every rule states why it may be a false positive: packers, DRM,
// anti-cheat, installers and mod loaders legitimately share many traits with malware.
#include <algorithm>
#include <array>
#include <cstdio>
#include <string>

#include "evidence_util.hpp"
#include "gk/analysis.hpp"
#include "gk/filetype.hpp"

namespace gk::analysis {

namespace {

using detail::loc;
using detail::make;
using namespace std::string_view_literals;

constexpr std::array kSystemProcesses = {
    "svchost.exe"sv, "csrss.exe"sv,   "lsass.exe"sv,   "winlogon.exe"sv,  "services.exe"sv,     "smss.exe"sv,
    "wininit.exe"sv, "explorer.exe"sv, "dllhost.exe"sv, "rundll32.exe"sv,  "conhost.exe"sv,      "taskhostw.exe"sv,
    "spoolsv.exe"sv, "runtimebroker.exe"sv, "sihost.exe"sv, "ctfmon.exe"sv, "dwm.exe"sv,         "audiodg.exe"sv,
    "searchindexer.exe"sv, "msmpeng.exe"sv, "lsaiso.exe"sv, "fontdrvhost.exe"sv, "wuauclt.exe"sv, "taskmgr.exe"sv};

constexpr std::array kTyposquats = {"svhost.exe"sv,  "scvhost.exe"sv, "svchosts.exe"sv, "svch0st.exe"sv,
                                    "csrsss.exe"sv,  "lsas.exe"sv,    "lsasss.exe"sv,   "expl0rer.exe"sv,
                                    "explorer32.exe"sv, "winlogin.exe"sv, "smsss.exe"sv, "dllhst.exe"sv,
                                    "rundll.exe"sv,  "conhosts.exe"sv, "spoolsvc.exe"sv, "taskhost32.exe"sv};

constexpr std::array kDocumentExtensions = {".pdf"sv, ".txt"sv, ".doc"sv, ".docx"sv, ".jpg"sv, ".jpeg"sv, ".png"sv,
                                            ".mp4"sv, ".mp3"sv, ".avi"sv, ".mkv"sv, ".xls"sv, ".xlsx"sv, ".zip"sv,
                                            ".rar"sv, ".7z"sv,  ".iso"sv, ".nfo"sv, ".html"sv};

// DLL names Windows resolves from the application directory first (search order), widely used by
// mod loaders (ReShade, ENB, ASI Loader, SpecialK, BepInEx doorstop), cracks and malware alike.
constexpr std::array kProxyDllNames = {
    "version.dll"sv, "winmm.dll"sv, "dinput8.dll"sv, "dinput.dll"sv, "d3d8.dll"sv, "d3d9.dll"sv, "d3d10.dll"sv,
    "d3d11.dll"sv, "d3d12.dll"sv, "dxgi.dll"sv, "ddraw.dll"sv, "opengl32.dll"sv, "dsound.dll"sv, "xinput1_3.dll"sv,
    "xinput1_4.dll"sv, "xinput9_1_0.dll"sv, "winhttp.dll"sv, "wininet.dll"sv, "dbghelp.dll"sv, "iphlpapi.dll"sv,
    "msimg32.dll"sv, "uxtheme.dll"sv, "cryptbase.dll"sv, "dwmapi.dll"sv, "userenv.dll"sv, "wtsapi32.dll"sv,
    "hid.dll"sv, "msacm32.dll"sv, "dwrite.dll"sv, "d2d1.dll"sv, "bink2w64.dll"sv, "binkw32.dll"sv};

// Drivers known to be abused to gain kernel access ("bring your own vulnerable driver"), from LOLDrivers.
constexpr std::array kAbusedDrivers = {"rtcore64.sys"sv,  "gdrv.sys"sv,         "dbutil_2_3.sys"sv,
                                       "iqvw64e.sys"sv,   "mhyprot2.sys"sv,     "kprocesshacker.sys"sv,
                                       "winring0x64.sys"sv, "winring0.sys"sv,   "procexp152.sys"sv,
                                       "asio64.sys"sv,    "asio.sys"sv,         "cpuz141_x64.sys"sv,
                                       "atillk64.sys"sv,  "amifldrv64.sys"sv,   "physmem.sys"sv, "ene.sys"sv};

struct PackerSection {
    std::string_view section;
    std::string_view packer;
    Risk severity;
    bool commercial;  // protectors used by DRM and anti-cheat
};
constexpr std::array kPackerSections = {
    PackerSection{"UPX0", "UPX", Risk::Low, false},          PackerSection{"UPX1", "UPX", Risk::Low, false},
    PackerSection{".aspack", "ASPack", Risk::Low, false},    PackerSection{".adata", "ASPack", Risk::Low, false},
    PackerSection{".MPRESS1", "MPRESS", Risk::Low, false},   PackerSection{".MPRESS2", "MPRESS", Risk::Low, false},
    PackerSection{".nsp0", "NsPack", Risk::Low, false},      PackerSection{".nsp1", "NsPack", Risk::Low, false},
    PackerSection{".petite", "Petite", Risk::Low, false},    PackerSection{"PEC2TO", "PECompact", Risk::Low, false},
    PackerSection{".pec2", "PECompact", Risk::Low, false},   PackerSection{".yP", "Y0da Protector", Risk::Low, false},
    PackerSection{".packed", "RLPack", Risk::Low, false},    PackerSection{".RLPack", "RLPack", Risk::Low, false},
    PackerSection{".kkrunchy", "kkrunchy", Risk::Low, false}, PackerSection{".themida", "Themida", Risk::Info, true},
    PackerSection{".winlice", "WinLicense", Risk::Info, true}, PackerSection{".vmp0", "VMProtect", Risk::Info, true},
    PackerSection{".vmp1", "VMProtect", Risk::Info, true},   PackerSection{".vmp2", "VMProtect", Risk::Info, true},
    PackerSection{".enigma1", "Enigma Protector", Risk::Info, true},
    PackerSection{".enigma2", "Enigma Protector", Risk::Info, true},
    PackerSection{".arch", "Denuvo/Arxan (provável)", Risk::Info, true}};

template <std::size_t N>
bool contains(const std::array<std::string_view, N>& set, std::string_view v) {
    return std::find(set.begin(), set.end(), v) != set.end();
}

std::string hex32(std::uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "0x%llX", static_cast<unsigned long long>(v));
    return buf;
}

Location section_loc(const pe::Section& s) {
    Location l = loc("section", "seção " + s.name);
    l.section = s.name;
    l.offset = s.raw_offset;
    l.rva = s.virtual_address;
    l.length = s.raw_size;
    return l;
}

std::string extension_before(const std::string& lower_name) {
    // "setup.pdf.exe" -> ".pdf"
    const auto last = lower_name.find_last_of('.');
    if (last == std::string::npos || last == 0) return {};
    const auto prev = lower_name.find_last_of('.', last - 1);
    if (prev == std::string::npos) return {};
    return lower_name.substr(prev, last - prev);
}

}  // namespace

void pe_evidence(const pe::PeInfo& info, ByteView data, const Subject& subject, std::vector<Evidence>& out,
                 FileFeatures& f) {
    const std::string lname = lower_ascii(subject.name);
    const std::string ext = extension_of(std::filesystem::path(subject.name));
    f.is_pe = true;
    f.is_dll = info.is_dll;
    f.is_driver = info.is_driver;
    f.is_dotnet = info.is_dotnet;
    f.machine = pe::machine_name(info.machine);
    f.version_info = info.version_info;
    for (const auto& e : info.exports) {
        if (f.exports.size() >= 256) break;
        if (!e.name.empty()) f.exports.push_back(e.name);
        if (!e.forwarder.empty() && f.export_forwarders.size() < 64) f.export_forwarders.push_back(e.forwarder);
    }
    for (const auto& imp : info.imports) {
        const std::string dll = lower_ascii(imp.dll);
        if (std::find(f.imports_dlls.begin(), f.imports_dlls.end(), dll) == f.imports_dlls.end()) f.imports_dlls.push_back(dll);
    }

    // ---- identity / masquerading (metadata; name-based rules are in name_evidence) --------------
    if (auto it = info.version_info.find("OriginalFilename"); it != info.version_info.end()) {
        const std::string original = lower_ascii(it->second);
        if (contains(kSystemProcesses, original) && original != lname) {
            Evidence e = make("PE.Masquerade.VersionInfo", "Metadados dizem ser um componente do Windows",
                              Source::Static, category::kStealth, Risk::Medium, Confidence::Medium,
                              "O recurso de versão declara o nome original \"" + it->second +
                                  "\", um processo do Windows, mas o arquivo se chama \"" + subject.name + "\".",
                              "Ferramentas que copiam metadados de outros programas também geram isso.");
            e.locations.push_back(loc("resource", "VERSIONINFO / OriginalFilename"));
            e.details["OriginalFilename"] = it->second;
            out.push_back(std::move(e));
        }
    }

    // ---- packing / obfuscation ----------------------------------------------------------------
    for (const auto& s : info.sections) {
        for (const auto& p : kPackerSections) {
            if (s.name != p.section) continue;
            if (std::find(f.packers.begin(), f.packers.end(), p.packer) == f.packers.end()) f.packers.emplace_back(p.packer);
            Evidence e = make("PE.Packer." + std::string(p.packer.substr(0, p.packer.find(' '))),
                              p.commercial ? "Protegido por protetor comercial (" + std::string(p.packer) + ")"
                                           : "Empacotado com " + std::string(p.packer),
                              Source::Static, category::kObfuscation, p.severity, Confidence::High,
                              "Seções típicas do empacotador/protetor " + std::string(p.packer) +
                                  ". O código real fica comprimido ou cifrado e só aparece em execução.",
                              p.commercial ? "Protetores comerciais são usados por DRM (Denuvo, VMProtect) e anti-cheats."
                                           : "Empacotadores reduzem tamanho de programas legítimos; nunca é prova isolada.");
            e.locations.push_back(section_loc(s));
            out.push_back(std::move(e));
            break;
        }
        if (s.name == ".bind") {
            Evidence e = make("PE.DRM.SteamStub", "DRM SteamStub presente", Source::Static, category::kInformational,
                              Risk::Info, Confidence::High,
                              "Executável com a proteção SteamStub (seção .bind) — típico do executável original da Steam.");
            e.locations.push_back(section_loc(s));
            e.tags.push_back("drm");
            out.push_back(std::move(e));
        }
        if (s.executable && s.raw_size > 4096 && s.entropy > 7.2) {
            Evidence e = make("PE.HighEntropyCode", "Código com entropia muito alta", Source::Static,
                              category::kObfuscation, Risk::Low, Confidence::Medium,
                              "A seção executável " + s.name + " tem entropia " + std::to_string(s.entropy).substr(0, 4) +
                                  " (máx. 8): conteúdo comprimido ou cifrado no lugar de código.",
                              "Empacotadores, DRM e anti-cheats legítimos produzem o mesmo efeito.");
            e.locations.push_back(section_loc(s));
            e.tags.push_back("packer");
            out.push_back(std::move(e));
        }
    }
    auto has_anomaly = [&](std::string_view code) {
        return std::find(info.anomalies.begin(), info.anomalies.end(), code) != info.anomalies.end();
    };
    if (has_anomaly("section_write_execute")) {
        Evidence e = make("PE.WriteExecuteSection", "Seção gravável e executável", Source::Static,
                          category::kObfuscation, Risk::Low, Confidence::Medium,
                          "Uma seção pode ser modificada e executada, padrão de código que se descompacta sozinho.",
                          "Comum em empacotadores e protetores legítimos.");
        for (const auto& s : info.sections) {
            if (s.writable && s.executable) e.locations.push_back(section_loc(s));
        }
        e.tags.push_back("packer");
        out.push_back(std::move(e));
    }
    if (has_anomaly("entrypoint_outside_sections")) {
        Evidence e = make("PE.EntryPoint.OutsideSections", "Ponto de entrada fora das seções", Source::Static,
                          category::kStructural, Risk::Medium, Confidence::Medium,
                          "O ponto de entrada (RVA " + hex32(info.entry_point) + ") não pertence a nenhuma seção.",
                          "Também ocorre em arquivos corrompidos.");
        Location l = loc("header", "AddressOfEntryPoint");
        l.rva = info.entry_point;
        e.locations.push_back(l);
        out.push_back(std::move(e));
    } else if (info.entry_section && (has_anomaly("entrypoint_in_non_executable_section") ||
                                       (has_anomaly("entrypoint_in_last_section") && info.sections.size() > 2))) {
        const auto& s = info.sections[*info.entry_section];
        Evidence e = make("PE.EntryPoint.Unusual", "Ponto de entrada em seção incomum", Source::Static,
                          category::kObfuscation, Risk::Low, Confidence::Low,
                          "O código começa na seção " + s.name + " (RVA " + hex32(info.entry_point) +
                              "), e não na seção de código usual — padrão de empacotadores.",
                          "Empacotadores e protetores legítimos fazem isso.");
        Location l = section_loc(s);
        l.rva = info.entry_point;
        e.locations.push_back(l);
        e.tags.push_back("packer");
        out.push_back(std::move(e));
    }
    if (!info.is_dotnet && !info.is_driver) {
        const bool dynamic = info.imports_function("LoadLibraryA") || info.imports_function("LoadLibraryW") ||
                             info.imports_function("LoadLibraryExA") || info.imports_function("LoadLibraryExW");
        const bool resolver = info.imports_function("GetProcAddress");
        if ((info.imports.size() <= 6 && dynamic && resolver) || (info.imports.empty() && !info.is_dll)) {
            Evidence e = make("PE.MinimalImports", "Importações mínimas (resolução dinâmica de APIs)", Source::Static,
                              category::kObfuscation, Risk::Low, Confidence::Medium,
                              "O executável importa só " + std::to_string(info.imports.size()) +
                                  " funções; as demais são localizadas em tempo de execução, o que esconde o que ele faz.",
                              "Empacotadores e alguns protetores de DRM produzem a mesma estrutura.");
            e.locations.push_back(loc("import", "tabela de importação"));
            e.tags.push_back("packer");
            out.push_back(std::move(e));
        }
    }

    // ---- embedded payloads ----------------------------------------------------------------------
    for (const auto& r : info.resources) {
        if (r.magic != "pe") continue;
        Evidence e = make("PE.EmbeddedExecutable.Resource", "Executável embutido em recurso", Source::Static,
                          category::kDropper, Risk::Low, Confidence::High,
                          "O recurso " + r.type + "/" + r.name + " contém outro executável (" +
                              std::to_string(r.size) + " bytes) que pode ser gravado e executado.",
                          "Instaladores e launchers legítimos embutem executáveis.");
        Location l = loc("resource", r.type + "/" + r.name);
        if (r.offset) l.offset = *r.offset;
        l.rva = r.rva;
        l.length = r.size;
        e.locations.push_back(l);
        out.push_back(std::move(e));
    }
    if (info.overlay_offset && !info.overlay_is_certificate_only) {
        Location l = loc("overlay", "dados anexados após a última seção");
        l.offset = *info.overlay_offset;
        l.length = static_cast<std::uint32_t>(std::min<std::uint64_t>(info.overlay_size, 0xFFFFFFFFu));
        if (info.overlay_magic == "pe") {
            Evidence e = make("PE.EmbeddedExecutable.Overlay", "Executável anexado ao final do arquivo", Source::Static,
                              category::kDropper, Risk::Medium, Confidence::High,
                              "Há um segundo executável após o fim da imagem PE (overlay).",
                              "Alguns instaladores fazem isso; em cracks e launchers é suspeito.");
            e.locations.push_back(l);
            out.push_back(std::move(e));
        } else if (info.overlay_magic == "zip" || info.overlay_magic == "7z" || info.overlay_magic == "rar" ||
                   info.overlay_magic == "cab" || info.overlay_magic == "nsis" || info.overlay_magic == "inno") {
            f.installer = info.overlay_magic;
            Evidence e = make("PE.Overlay.Archive", "Instalador/autoextraível com arquivo anexado", Source::Static,
                              category::kInformational, Risk::Info, Confidence::High,
                              "O executável carrega um pacote " + info.overlay_magic + " anexado (" +
                                  std::to_string(info.overlay_size) + " bytes); o conteúdo é analisado separadamente.");
            e.locations.push_back(l);
            out.push_back(std::move(e));
        } else if (info.overlay_size > (1u << 20) && info.overlay_entropy > 7.9) {
            Evidence e = make("PE.Overlay.HighEntropy", "Grande bloco de dados cifrados/comprimidos anexado",
                              Source::Static, category::kInformational, Risk::Info, Confidence::Low,
                              std::to_string(info.overlay_size) + " bytes de alta entropia após a imagem PE.",
                              "Instaladores e repacks guardam dados comprimidos assim.");
            e.locations.push_back(l);
            out.push_back(std::move(e));
        }
    }

    // ---- other structural facts -------------------------------------------------------------------
    if (info.tls_callbacks > 0) {
        Evidence e = make("PE.TlsCallbacks", "Callbacks TLS (código executado antes do ponto de entrada)",
                          Source::Static, category::kInformational, Risk::Info, Confidence::High,
                          std::to_string(info.tls_callbacks) + " callback(s) TLS — técnica usada por proteções anti-depuração.",
                          "Usado por runtimes, DRM e anti-cheats.");
        e.locations.push_back(loc("header", "diretório TLS"));
        out.push_back(std::move(e));
    }
    if (info.manifest_execution_level == "requireAdministrator") {
        Evidence e = make("PE.RequiresAdmin", "Pede privilégios de administrador", Source::Static,
                          category::kInformational, Risk::Info, Confidence::High,
                          "O manifesto exige elevação (requireAdministrator).", "Instaladores pedem administrador legitimamente.");
        e.locations.push_back(loc("resource", "RT_MANIFEST"));
        out.push_back(std::move(e));
    }
    for (const auto& d : info.debug) {
        if (d.pdb_path.empty()) continue;
        const std::string pdb = lower_ascii(d.pdb_path);
        for (std::string_view word : {"stealer"sv, "grabber"sv, "keylog"sv, "crypter"sv, "injector"sv, "rootkit"sv,
                                      "ransom"sv, "\\rat\\"sv, "_rat"sv, "botnet"sv, "payload"sv, "\\stub"sv,
                                      "miner"sv, "token_grab"sv, "loader\\"sv}) {
            if (pdb.find(word) == std::string::npos) continue;
            Evidence e = make("PE.Debug.SuspiciousProjectName", "Nome do projeto de compilação sugere malware",
                              Source::Static, category::kTrojan, Risk::Medium, Confidence::Medium,
                              "O caminho de depuração gravado pelo compilador é \"" + d.pdb_path +
                                  "\" (contém \"" + std::string(word) + "\").",
                              "Projetos legítimos raramente usam esses nomes; pode ser coincidência.");
            Location l = loc("header", "diretório de depuração (PDB)");
            l.excerpt = printable_excerpt_text(d.pdb_path, 160);
            e.locations.push_back(l);
            out.push_back(std::move(e));
            break;
        }
    }
    if (has_anomaly("section_raw_beyond_eof") || has_anomaly("section_table_abort") ||
        has_anomaly("import_directory_truncated")) {
        Evidence e = make("PE.Structure.Truncated", "Estrutura PE truncada ou inconsistente", Source::Static,
                          category::kStructural, Risk::Low, Confidence::Medium,
                          "Partes declaradas no cabeçalho não existem no arquivo (" +
                              std::to_string(info.anomalies.size()) + " anomalia(s)).",
                          "Downloads incompletos produzem o mesmo efeito: confira o hash do arquivo.");
        for (const auto& a : info.anomalies) e.details["anomalia_" + std::to_string(e.details.size())] = a;
        out.push_back(std::move(e));
    }

    // ---- drivers --------------------------------------------------------------------------------
    if (info.is_driver) {
        if (contains(kAbusedDrivers, lname)) {
            Evidence e = make("PE.Driver.KnownAbused", "Driver conhecido por ser abusado (BYOVD)", Source::Static,
                              category::kRootkit, Risk::Medium, Confidence::Medium,
                              "\"" + subject.name + "\" é um driver legítimo com vulnerabilidade conhecida, usado por "
                                                    "malware para obter acesso ao kernel e desativar proteções.",
                              "Ferramentas de hardware (overclock, RGB, monitoramento) e alguns anti-cheats o instalam.");
            e.locations.push_back(loc("header", "nome do arquivo"));
            out.push_back(std::move(e));
        }
        const bool terminate = info.imports_function("ZwTerminateProcess") && info.imports_function("PsLookupProcessByProcessId");
        if (terminate) {
            Evidence e = make("PE.Driver.ProcessKiller", "Driver capaz de encerrar processos", Source::Static,
                              category::kRootkit, Risk::Medium, Confidence::Low,
                              "Importa ZwTerminateProcess e PsLookupProcessByProcessId: encerra processos a partir do "
                              "kernel, técnica usada para derrubar antivírus.",
                              "Anti-cheats também encerram processos pelo kernel.");
            e.locations.push_back(loc("import", "ntoskrnl.exe"));
            out.push_back(std::move(e));
        }
        if (info.imports_function("MmMapIoSpace") || info.imports_function("MmMapIoSpaceEx")) {
            Evidence e = make("PE.Driver.PhysicalMemory", "Driver mapeia memória física", Source::Static,
                              category::kRootkit, Risk::Low, Confidence::Low,
                              "Importa MmMapIoSpace: acesso direto à memória física.",
                              "Drivers de hardware e monitoramento fazem isso.");
            e.locations.push_back(loc("import", "ntoskrnl.exe"));
            out.push_back(std::move(e));
        }
        Evidence e = make("PE.Driver", "Driver de kernel", Source::Static, category::kInformational, Risk::Info,
                          Confidence::High,
                          "Componente que roda no kernel do Windows. A assinatura digital é o principal critério de confiança.",
                          "Anti-cheats e periféricos usam drivers legítimos.");
        out.push_back(std::move(e));
    }

    // ---- DLL proxy (search-order) ------------------------------------------------------------------
    if (info.is_dll && contains(kProxyDllNames, lname)) {
        std::size_t forwarded = 0;
        for (const auto& ex : info.exports) {
            if (!ex.forwarder.empty()) ++forwarded;
        }
        Evidence e = make("PE.DllProxy", "DLL com nome de biblioteca do Windows (proxy/sideloading)", Source::Static,
                          category::kDllHijacking, Risk::Info, Confidence::High,
                          "\"" + subject.name + "\" é carregada pelo jogo no lugar da biblioteca do Windows" +
                              (forwarded ? " e encaminha " + std::to_string(forwarded) + " função(ões) para a original." : "."),
                          "ReShade, ENB, ASI Loader, SpecialK, DXVK, BepInEx e muitos cracks usam esta técnica.");
        e.locations.push_back(loc("export", "tabela de exportação"));
        e.tags.push_back("dll-proxy");
        out.push_back(std::move(e));
    }
    (void)data;
}

void name_evidence(const Subject& subject, bool executable_content, std::vector<Evidence>& out) {
    const std::string lname = lower_ascii(subject.name);
    const std::string ext = extension_of(std::filesystem::path(subject.name));
    static constexpr std::array kRunnable = {".exe"sv, ".scr"sv, ".com"sv, ".pif"sv, ".bat"sv, ".cmd"sv, ".lnk"sv,
                                             ".vbs"sv, ".vbe"sv, ".js"sv,  ".jse"sv, ".wsf"sv, ".hta"sv, ".ps1"sv,
                                             ".msi"sv, ".cpl"sv, ".jar"sv};
    const bool runnable = executable_content || contains(kRunnable, ext);
    if (subject.name.find("\xE2\x80\xAE") != std::string::npos) {  // U+202E RIGHT-TO-LEFT OVERRIDE
        Evidence e = make("NAME.RightToLeftOverride", "Nome com caractere que inverte o texto (RLO)", Source::Static,
                          category::kStealth, Risk::High, Confidence::High,
                          "O nome contém o caractere invisível U+202E, que faz \"exe.pdf\" aparecer como \"fdp.exe\" e "
                          "esconde a extensão real.",
                          "Não há uso legítimo deste caractere em nomes de arquivos de jogos.");
        e.locations.push_back(loc("header", "nome do arquivo"));
        out.push_back(std::move(e));
    }
    if (!runnable) return;
    if (contains(kSystemProcesses, lname)) {
        Evidence e = make("NAME.SystemProcessName", "Nome de processo do Windows fora da pasta do sistema",
                          Source::Static, category::kStealth, Risk::High, Confidence::Medium,
                          "O arquivo usa o nome de um processo do Windows (" + subject.name +
                              "). Processos genuínos ficam em C:\\Windows\\System32; uma cópia junto de um jogo é uma "
                              "técnica comum para se esconder no Gerenciador de Tarefas.",
                          "Alguns instaladores trazem cópias de ferramentas do sistema, mas jogos e cracks não precisam disso.");
        e.locations.push_back(loc("header", "nome do arquivo"));
        out.push_back(std::move(e));
    }
    if (contains(kTyposquats, lname)) {
        Evidence e = make("NAME.Typosquat", "Nome imita um processo do Windows", Source::Static, category::kStealth,
                          Risk::High, Confidence::High,
                          "O nome \"" + subject.name + "\" imita um processo do sistema com uma grafia alterada.",
                          "Muito improvável em software legítimo.");
        e.locations.push_back(loc("header", "nome do arquivo"));
        out.push_back(std::move(e));
    }
    if (const std::string inner = extension_before(lname); !inner.empty() && contains(kDocumentExtensions, inner)) {
        Evidence e = make("NAME.DoubleExtension", "Extensão dupla (documento falso)", Source::Static, category::kStealth,
                          Risk::High, Confidence::High,
                          "O nome termina como documento/mídia (" + inner + ") mas o arquivo é executável (" + ext +
                              "). O Windows esconde extensões conhecidas, então o usuário vê apenas o nome falso.",
                          "Improvável em arquivos legítimos.");
        e.locations.push_back(loc("header", "nome do arquivo"));
        out.push_back(std::move(e));
    }
}

}  // namespace gk::analysis
