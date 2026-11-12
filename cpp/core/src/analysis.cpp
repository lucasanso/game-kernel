// Per-object analysis orchestration (context-free evidence; risk is decided later by the risk engine).
#include "gk/analysis.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <set>

#include "evidence_util.hpp"
#include "gk/file_view.hpp"
#include "gk/filetype.hpp"
#include "gk/hash.hpp"

namespace gk::analysis {

namespace {

using detail::loc;
using detail::make;

constexpr std::string_view kArchiveKinds[] = {"zip", "jar", "7z", "rar", "gzip", "bzip2", "xz", "tar", "cab", "iso", "zstd"};

bool archive_kind(std::string_view kind) {
    return std::find(std::begin(kArchiveKinds), std::end(kArchiveKinds), kind) != std::end(kArchiveKinds);
}

double now_seconds() {
    using namespace std::chrono;
    return duration<double>(system_clock::now().time_since_epoch()).count();
}

std::string base_name(const std::string& path) {
    const auto pos = path.find_last_of("/\\");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

void add_engine(FileResult& r, const char* name) {
    if (std::find(r.engines.begin(), r.engines.end(), name) == r.engines.end()) r.engines.emplace_back(name);
}

void add_reason(FileResult& r, const std::string& reason) {
    r.status = r.status == AnalysisStatus::Error ? r.status : AnalysisStatus::Partial;
    if (std::find(r.status_reasons.begin(), r.status_reasons.end(), reason) == r.status_reasons.end()) {
        r.status_reasons.push_back(reason);
    }
}

// Byte offset -> (section, rva) for PE files, used to locate YARA and indicator matches.
void locate(Location& l, const pe::PeInfo* pe) {
    if (pe == nullptr || !l.offset) return;
    if (auto s = pe->section_for_offset(*l.offset)) l.section = pe->sections[*s].name;
    if (auto rva = pe->offset_to_rva(*l.offset)) l.rva = *rva;
}

yara::ScanOptions scan_options(const Subject& s, const std::string& kind, const Options& opt, CancelToken* cancel) {
    yara::ScanOptions o;
    o.timeout_seconds = opt.yara_timeout_seconds;
    o.cancel = cancel;
    o.max_instances_per_string = 3;
    o.max_strings_per_rule = 12;
    o.externals = {s.name, s.path, lower_ascii(extension_of(std::filesystem::path(s.name))), kind};
    return o;
}

// Detection rules -> evidence.
void detection_evidence(const yara::ScanResult& scan, const pe::PeInfo* pe, std::vector<Evidence>& out) {
    for (const auto& m : scan.matches) {
        auto meta = [&](const char* key, const std::string& fallback = {}) {
            auto it = m.meta.find(key);
            return it == m.meta.end() ? fallback : it->second;
        };
        std::string cat = meta("category", std::string(category::kGenericMalware));
        if (!category::known(cat)) cat = std::string(category::kGenericMalware);
        const std::string verdict = lower_ascii(meta("verdict", "suspicious"));
        Evidence e = make("YARA." + m.rule, meta("description", m.rule), Source::Yara, cat,
                          parse_risk(meta("severity", "MEDIUM"), Risk::Medium),
                          parse_confidence(meta("confidence", "MEDIUM"), Confidence::Medium), meta("description"),
                          meta("fp_note"), "yara");
        e.details["rule"] = m.rule;
        e.details["verdict"] = verdict;
        if (!meta("reference").empty()) e.details["reference"] = meta("reference");
        e.tags.push_back("verdict:" + verdict);
        for (const auto& t : m.tags) e.tags.push_back(t);
        for (const auto& s : m.strings) {
            if (e.locations.size() >= 8) break;
            Location l = loc("yara_match", s.identifier);
            l.offset = s.offset;
            l.length = s.length;
            l.excerpt = s.excerpt;
            locate(l, pe);
            e.locations.push_back(l);
        }
        if (e.locations.empty()) e.locations.push_back(loc("yara_match", "condição estrutural (sem strings)"));
        out.push_back(std::move(e));
    }
}

// Indicator rules -> hits (+ packer/installer markers into features).
void indicator_hits(const yara::ScanResult& scan, const pe::PeInfo* pe, std::vector<IndicatorHit>& hits,
                    FileFeatures& f, const std::string* text_for_lines) {
    for (const auto& m : scan.matches) {
        if (m.rule.rfind("PKR_", 0) == 0) {
            auto it = m.meta.find("marker");
            if (it == m.meta.end()) continue;
            if (std::find(f.packers.begin(), f.packers.end(), it->second) == f.packers.end()) f.packers.push_back(it->second);
            if ((it->second == "Inno Setup" || it->second == "NSIS" || it->second == "InstallShield") && !f.installer) {
                f.installer = it->second;
            }
            continue;
        }
        if (m.rule.rfind("IND_", 0) != 0) continue;
        IndicatorHit h;
        h.id = m.rule.substr(4);
        h.group = m.meta.count("group") ? m.meta.at("group") : h.id;
        h.description = m.meta.count("description") ? m.meta.at("description") : h.id;
        std::set<std::string> seen;
        for (const auto& s : m.strings) {
            if (seen.insert(lower_ascii(s.excerpt)).second) h.matched.push_back(s.excerpt);
            if (h.locations.size() >= 6) continue;
            Location l = loc("string", h.description);
            l.offset = s.offset;
            l.length = s.length;
            l.excerpt = s.excerpt;
            if (text_for_lines != nullptr) {
                l.kind = "line";
                l.line = static_cast<std::uint32_t>(
                    1 + std::count(text_for_lines->begin(),
                                   text_for_lines->begin() + static_cast<std::ptrdiff_t>(std::min<std::uint64_t>(s.offset, text_for_lines->size())),
                                   '\n'));
            }
            locate(l, pe);
            h.locations.push_back(std::move(l));
        }
        hits.push_back(std::move(h));
    }
}

void merge_hits(std::vector<IndicatorHit>& into, std::vector<IndicatorHit>&& more) {
    for (auto& h : more) {
        auto it = std::find_if(into.begin(), into.end(), [&](const IndicatorHit& x) { return x.id == h.id; });
        if (it == into.end()) {
            into.push_back(std::move(h));
        } else {
            for (auto& l : h.locations) {
                if (it->locations.size() < 8) it->locations.push_back(std::move(l));
            }
            for (auto& s : h.matched) it->matched.push_back(std::move(s));
        }
    }
}

std::size_t count_of(const std::string& haystack, std::string_view needle) {
    std::size_t n = 0;
    for (std::size_t pos = haystack.find(needle); pos != std::string::npos; pos = haystack.find(needle, pos + needle.size())) ++n;
    return n;
}

class Analyzer {
public:
    Analyzer(const RuleSet& rules, const Options& opt, CancelToken* cancel) : rules_(rules), opt_(opt), cancel_(cancel) {}

    Output run(ByteView data, const Subject& s, bool allow_archives);

private:
    void scripts(ByteView data, const Subject& s, FileResult& r, std::vector<IndicatorHit>& hits);
    void shortcut(ByteView data, const Subject& s, FileResult& r, std::vector<IndicatorHit>& hits);
    void archives(ByteView data, const Subject& s, Output& out);
    std::vector<IndicatorHit> scan_text(const std::string& text, const Subject& s, FileResult& r, const char* label);

    const RuleSet& rules_;
    const Options& opt_;
    CancelToken* cancel_;
};

std::vector<IndicatorHit> Analyzer::scan_text(const std::string& text, const Subject& s, FileResult& r, const char* label) {
    std::vector<IndicatorHit> hits;
    if (!rules_.indicators) return hits;
    const auto scan = rules_.indicators->scan(ByteView(text), scan_options(s, r.file_type, opt_, cancel_));
    if (scan.timed_out) add_reason(r, "tempo limite do YARA excedido");
    indicator_hits(scan, nullptr, hits, r.features, &text);
    for (auto& h : hits) {
        for (auto& l : h.locations) {
            if (label != nullptr) l.description = std::string(label) + ": " + l.description;
        }
    }
    return hits;
}

void Analyzer::scripts(ByteView data, const Subject& s, FileResult& r, std::vector<IndicatorHit>& hits) {
    add_engine(r, "scripts");
    const std::string text = script_text(data, opt_.max_script_bytes);
    if (data.size() > opt_.max_script_bytes) add_reason(r, "script maior que o limite: analisado só o início");
    r.features.text_head = printable_excerpt_text(text, 200);
    merge_hits(hits, scan_text(text, s, r, nullptr));
    if (opt_.deep) {
        for (const auto& p : decode_script_payloads(text)) {
            Location l = loc("line", p.kind == "encoded_command" ? "comando PowerShell codificado" : "bloco Base64");
            l.line = p.line;
            if (p.is_pe) {
                Evidence e = make("SCRIPT.EmbeddedExecutable", "Executável escondido em Base64 dentro do script",
                                  Source::Static, category::kDropper, Risk::High, Confidence::High,
                                  "O script contém um programa (.exe/.dll) codificado em Base64, pronto para ser gravado e executado.",
                                  "Instaladores legítimos não embutem executáveis em scripts.", "scripts");
                e.locations.push_back(l);
                r.evidences.push_back(std::move(e));
                continue;
            }
            l.excerpt = printable_excerpt_text(p.text, 160);
            Evidence e = make(p.kind == "encoded_command" ? "SCRIPT.EncodedPowerShell" : "SCRIPT.Base64Payload",
                              p.kind == "encoded_command" ? "Comando PowerShell codificado (Base64)" : "Conteúdo escondido em Base64",
                              Source::Static, category::kMaliciousScript, Risk::Medium, Confidence::Medium,
                              "Parte do script só é legível depois de decodificada; o conteúdo decodificado também foi analisado.",
                              "Alguns administradores codificam comandos para evitar problemas de aspas.", "scripts");
            e.locations.push_back(l);
            e.details["decodificado"] = printable_excerpt_text(p.text, 400);
            r.evidences.push_back(std::move(e));
            merge_hits(hits, scan_text(p.text, s, r, "conteúdo decodificado"));
        }
    }
    // Obfuscation metrics (character-code construction, caret escaping, extreme line lengths).
    const std::string lower = lower_ascii(text);
    const std::size_t char_codes = count_of(lower, "[char]") + count_of(lower, "chr(") + count_of(lower, "chrw(") +
                                   count_of(lower, "fromcharcode");
    std::size_t carets = 0;
    std::size_t longest = 0;
    std::size_t current = 0;
    for (char c : text) {
        carets += c == '^' ? 1 : 0;
        current = c == '\n' ? 0 : current + 1;
        longest = std::max(longest, current);
    }
    const bool batch = r.file_type == "bat";
    if (char_codes >= 20 || (batch && carets >= 40 && carets * 20 >= text.size()) || longest > 8000) {
        Evidence e = make("SCRIPT.Obfuscated", "Script ofuscado", Source::Heuristic, category::kObfuscation,
                          Risk::Medium, Confidence::Medium,
                          "O texto é construído caractere a caractere, usa escapes em excesso ou linhas gigantes para "
                          "esconder o que executa.",
                          "Geradores automáticos de scripts às vezes produzem linhas longas.", "scripts");
        e.details["construcoes_por_codigo"] = std::to_string(char_codes);
        e.details["escapes_circunflexo"] = std::to_string(carets);
        e.details["maior_linha"] = std::to_string(longest);
        r.evidences.push_back(std::move(e));
    }
}

void Analyzer::shortcut(ByteView data, const Subject& s, FileResult& r, std::vector<IndicatorHit>& hits) {
    add_engine(r, "lnk");
    if (r.file_type == "url") {
        const std::string text = script_text(data, 64 * 1024);
        const std::string lower = lower_ascii(text);
        const auto pos = lower.find("url=");
        if (pos != std::string::npos) {
            const std::string url = text.substr(pos + 4, text.find_first_of("\r\n", pos) - pos - 4);
            r.features.text_head = printable_excerpt_text(url, 300);
            const std::string lu = lower_ascii(url);
            if (lu.rfind("file:", 0) == 0 || lu.rfind("javascript:", 0) == 0 || lu.find(".exe") != std::string::npos ||
                lu.find("\\\\") == 0) {
                Evidence e = make("LNK.UrlShortcutToProgram", "Atalho de internet aponta para programa/arquivo",
                                  Source::Static, category::kMaliciousScript, Risk::Medium, Confidence::Medium,
                                  "O atalho .url abre \"" + printable_excerpt_text(url, 120) +
                                      "\" em vez de um site — truque para executar arquivos ao clicar.",
                                  "Atalhos para documentos locais também usam file:.", "lnk");
                r.evidences.push_back(std::move(e));
            }
        }
        return;
    }
    const LnkInfo lnk = parse_lnk(data);
    if (!lnk.valid) {
        add_reason(r, "atalho LNK com estrutura inválida");
        return;
    }
    r.features.text_head = printable_excerpt_text(lnk.target + " " + lnk.arguments, 300);
    const std::string target = lower_ascii(base_name(lnk.target));
    static constexpr std::string_view kInterpreters[] = {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe",
                                                         "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
                                                         "msiexec.exe", "bitsadmin.exe", "certutil.exe", "conhost.exe",
                                                         "forfiles.exe", "wmic.exe"};
    const bool interpreter = std::find(std::begin(kInterpreters), std::end(kInterpreters), target) != std::end(kInterpreters);
    Location l = loc("member", "alvo do atalho");
    l.excerpt = printable_excerpt_text(lnk.target + " " + lnk.arguments, 160);
    if (interpreter && !lnk.arguments.empty()) {
        Evidence e = make("LNK.RunsCommand", "Atalho executa um comando do sistema", Source::Static,
                          category::kMaliciousScript, Risk::Medium, Confidence::Medium,
                          "O atalho chama " + target + " com argumentos, em vez de abrir o jogo diretamente.",
                          "Atalhos administrativos legítimos existem, mas não costumam vir dentro de jogos.", "lnk");
        e.locations.push_back(l);
        e.details["alvo"] = lnk.target;
        e.details["argumentos"] = printable_excerpt_text(lnk.arguments, 400);
        r.evidences.push_back(std::move(e));
    }
    const std::size_t leading_ws = lnk.arguments.find_first_not_of(" \t");
    if (lnk.arguments.size() > 260 || (leading_ws != std::string::npos && leading_ws > 40)) {
        Evidence e = make("LNK.HiddenArguments", "Argumentos escondidos no atalho", Source::Static, category::kStealth,
                          Risk::High, Confidence::Medium,
                          "Os argumentos são longos ou começam com muitos espaços, o que os esconde na janela de "
                          "propriedades do atalho.",
                          "Improvável em atalhos legítimos.", "lnk");
        e.locations.push_back(l);
        r.evidences.push_back(std::move(e));
    }
    const std::string icon = lower_ascii(lnk.icon_location);
    if (interpreter && (icon.find("shell32") != std::string::npos || icon.find("imageres") != std::string::npos ||
                        icon.find(".pdf") != std::string::npos || icon.find(".ico") != std::string::npos)) {
        Evidence e = make("LNK.IconDisguise", "Atalho disfarçado com ícone de outro tipo de arquivo", Source::Static,
                          category::kStealth, Risk::Medium, Confidence::Low,
                          "O atalho executa " + target + " mas exibe o ícone \"" + lnk.icon_location + "\".",
                          "Usuários avançados personalizam ícones.", "lnk");
        e.locations.push_back(l);
        r.evidences.push_back(std::move(e));
    }
    if (!lnk.arguments.empty()) {
        merge_hits(hits, scan_text(lnk.arguments, s, r, "argumentos do atalho"));
        for (const auto& p : decode_script_payloads(lnk.arguments)) {
            if (p.text.empty()) continue;
            merge_hits(hits, scan_text(p.text, s, r, "comando decodificado do atalho"));
        }
    }
}

void Analyzer::archives(ByteView data, const Subject& s, Output& out) {
    FileResult& r = out.result;
    add_engine(r, "archive");
    archive::Visitor visitor;
    std::string current_kind;
    visitor.on_entry = [&](const archive::Member& m) {
        if (m.encrypted && !m.is_directory) {
            // Encrypted members are never read: report them so the user sees exactly what was not analysed.
            FileResult skipped;
            skipped.path = s.path + "::" + m.path;
            skipped.name = base_name(m.name);
            skipped.directory = s.path;
            skipped.extension = extension_of(std::filesystem::path(skipped.name));
            skipped.size = m.declared_size;
            skipped.container = s.container.value_or(s.path);
            skipped.member_path = s.member_path ? *s.member_path + "::" + m.path : m.path;
            skipped.depth = s.depth + static_cast<int>(m.depth) + 1;
            skipped.status = AnalysisStatus::Skipped;
            skipped.status_reasons.emplace_back("membro protegido por senha");
            skipped.analyzed_at = now_seconds();
            out.members.push_back(std::move(skipped));
        }
        return archive::Want::Read;
    };
    visitor.on_data = [&](const archive::Member& m, ByteView member_data) {
        Subject sub;
        sub.path = s.path + "::" + m.path;
        sub.name = base_name(m.name);
        sub.directory = s.path;
        sub.container = s.container.value_or(s.path);
        sub.member_path = s.member_path ? *s.member_path + "::" + m.path : m.path;
        sub.depth = s.depth + static_cast<int>(m.depth) + 1;
        Output member = run(member_data, sub, false);
        member.result.size = m.size_known ? m.declared_size : m.bytes_read;
        if (!m.complete) add_reason(member.result, "membro lido parcialmente (limite de tamanho ou erro de leitura)");
        for (const auto& a : m.anomalies) {
            if (a == "path_traversal" || a == "absolute_path") {
                Evidence e = make(a == "path_traversal" ? "ARCHIVE.PathTraversal" : "ARCHIVE.AbsolutePath",
                                  a == "path_traversal" ? "Caminho que escapa da pasta de extração"
                                                        : "Caminho absoluto dentro do compactado",
                                  Source::Static, category::kSystemModification,
                                  a == "path_traversal" ? Risk::High : Risk::Medium, Confidence::High,
                                  "Ao extrair, este membro seria gravado fora da pasta escolhida (\"" + m.name +
                                      "\") — técnica para plantar arquivos no sistema.",
                                  "Compactados legítimos não usam esses caminhos.", "archive");
                Location l = loc("member", m.path);
                e.locations.push_back(l);
                member.result.evidences.push_back(std::move(e));
            }
        }
        current_kind = member.result.file_type;
        out.members.push_back(std::move(member.result));
    };
    visitor.is_archive = [&](const archive::Member&, ByteView) { return archive_kind(current_kind); };
    const archive::Report report = archive::walk(data, opt_.archive_limits, visitor, cancel_);

    if (!report.complete) {
        for (const auto& a : report.anomalies) add_reason(r, "compactado: " + a);
    }
    for (const auto& a : report.anomalies) {
        if (a == "decompression_bomb") {
            Evidence e = make("ARCHIVE.DecompressionBomb", "Bomba de descompactação", Source::Static,
                              category::kStructural, Risk::High, Confidence::High,
                              "A taxa de compressão ultrapassa o limite seguro: o conteúdo cresceria a ponto de esgotar "
                              "disco/memória. A leitura foi interrompida.",
                              "Arquivos com longas sequências repetidas comprimem muito, mas não nesta proporção.", "archive");
            r.evidences.push_back(std::move(e));
        }
    }
    if (report.encrypted_entries) {
        Evidence e = make("ARCHIVE.Encrypted", "Conteúdo protegido por senha", Source::Static, category::kStealth,
                          Risk::Medium, Confidence::Medium,
                          "Há membros cifrados que não puderam ser analisados. Proteger o conteúdo com senha é uma "
                          "técnica conhecida para impedir a varredura por antivírus.",
                          "Alguns distribuidores protegem arquivos com senha por outros motivos.", "archive");
        r.evidences.push_back(std::move(e));
        add_reason(r, "membros protegidos por senha não analisados");
    }
    if (std::find(report.anomalies.begin(), report.anomalies.end(), "corrupt") != report.anomalies.end()) {
        Evidence e = make("ARCHIVE.Corrupt", "Compactado corrompido ou incompleto", Source::Static,
                          category::kStructural, Risk::Low, Confidence::Medium,
                          "Não foi possível ler todo o conteúdo: " +
                              (report.errors.empty() ? std::string("erro de formato") : report.errors.front()),
                          "Downloads incompletos causam isso: confira o hash/SFV do download.", "archive");
        r.evidences.push_back(std::move(e));
    }
    r.features.packers.insert(r.features.packers.end(), report.nested_formats.begin(), report.nested_formats.end());
    if (!report.format.empty()) r.features.installer = r.features.installer.value_or(report.format);
}

Output Analyzer::run(ByteView data, const Subject& s, bool allow_archives) {
    Output out;
    FileResult& r = out.result;
    r.path = s.path;
    r.name = s.name;
    r.directory = s.directory;
    r.extension = extension_of(std::filesystem::path(s.name));
    r.size = data.size();
    r.container = s.container;
    r.member_path = s.member_path;
    r.depth = s.depth;
    r.analyzed_at = now_seconds();

    {
        Sha256 sha;
        Md5 md5;
        sha.update(data);
        md5.update(data);
        r.sha256 = to_hex(sha.finish());
        r.md5 = to_hex(md5.finish());
    }
    add_engine(r, "hash");
    const TypeInfo type = identify(data.prefix(kHeaderSize), r.extension, data.clamp(kIsoProbeOffset, kIsoProbeSize));
    r.file_type = type.kind;
    r.features.file_type = type.kind;
    add_engine(r, "filetype");
    if (type.disguised) {
        Evidence e = make("FILE.DisguisedExecutable", "Executável disfarçado de arquivo de dados", Source::Static,
                          category::kStealth, Risk::High, Confidence::High,
                          "O conteúdo é " + type.description + ", mas a extensão \"" + r.extension +
                              "\" sugere outro tipo de arquivo.",
                          "Alguns jogos guardam bibliotecas com extensões próprias; confira se o arquivo é carregado pelo jogo.");
        e.locations.push_back(loc("header", "assinatura do arquivo (magic bytes)"));
        r.evidences.push_back(std::move(e));
    }

    name_evidence(s, type.group == "executable", r.evidences);
    add_engine(r, "names");

    const bool large = data.size() > opt_.max_analysis_bytes;
    if (large) add_reason(r, "arquivo maior que o limite de análise: análise estrutural limitada");
    const bool is_pe_kind = type.kind.rfind("pe_", 0) == 0;
    std::optional<pe::PeInfo> pe_info;
    if (is_pe_kind) {
        add_engine(r, "pe");
        pe_info = pe::parse(data);
        if (!pe_info->valid) {
            add_reason(r, "estrutura PE inválida: " + pe_info->error);
            pe_info.reset();
        } else {
            pe_evidence(*pe_info, data, s, r.evidences, r.features);
        }
    }
    const pe::PeInfo* pe = pe_info ? &*pe_info : nullptr;

    std::vector<IndicatorHit> hits;
    // An archive that will be expanded is not content-scanned itself: each member is analysed on its own
    // (scanning the container too would repeat every finding of uncompressed members).
    const bool expands = allow_archives && opt_.deep && archive_kind(type.kind);
    const bool scan_content = !large && !expands && type.group != "data" && type.group != "document";
    if (rules_.detection && !large && !expands) {
        add_engine(r, "yara");
        const auto scan = rules_.detection->scan(data, scan_options(s, type.kind, opt_, cancel_));
        if (scan.timed_out) add_reason(r, "tempo limite do YARA excedido");
        if (!scan.error.empty()) add_reason(r, "YARA: " + scan.error);
        detection_evidence(scan, pe, r.evidences);
    }
    if (rules_.indicators && scan_content && type.group != "script") {
        add_engine(r, "indicators");
        const auto scan = rules_.indicators->scan(data, scan_options(s, type.kind, opt_, cancel_));
        if (scan.timed_out) add_reason(r, "tempo limite do YARA excedido");
        indicator_hits(scan, pe, hits, r.features, nullptr);
    }
    if (type.group == "script") scripts(data, s, r, hits);
    if (type.group == "shortcut") shortcut(data, s, r, hits);

    std::vector<Location> netlits;
    if (scan_content && (type.group == "executable" || type.group == "script" || type.group == "shortcut")) {
        netlits = network_literals(data);
        for (auto& l : netlits) locate(l, pe);
    }
    capability_evidence(hits, pe, type.group == "script", netlits, r.evidences);

    // Small text files may be crack/emulator configuration: keep their beginning for folder context.
    if (!r.features.text_head && type.group == "text" && data.size() <= 64 * 1024) {
        r.features.text_head = printable_excerpt_text(script_text(data, 4096), 1000);
    }

    const bool sfx = pe != nullptr && r.features.installer &&
                     (*r.features.installer == "zip" || *r.features.installer == "7z" || *r.features.installer == "rar" ||
                      *r.features.installer == "cab");
    if (allow_archives && !large && (archive_kind(type.kind) || sfx)) {
        if (opt_.deep) {
            archives(data, s, out);
        } else {
            add_reason(r, "conteúdo do compactado não expandido no modo rápido");
        }
    }
    if (type.kind == "corrupt_archive") add_reason(r, "compactado com cabeçalho inválido");
    if (type.kind == "msi" || type.kind == "pyinstaller_archive") add_reason(r, "formato sem extração interna nesta versão");
    return out;
}

}  // namespace

RuleSet RuleSet::load(const std::vector<std::filesystem::path>& detection_dirs, const std::filesystem::path& indicator_file) {
    RuleSet set;
    std::map<std::string, std::filesystem::path> by_name;
    for (const auto& dir : detection_dirs) {
        for (const auto& f : yara::rule_files_in(dir)) by_name[f.filename().string()] = f;
    }
    std::vector<std::filesystem::path> files;
    for (const auto& [_, p] : by_name) files.push_back(p);
    if (!files.empty()) set.detection = yara::Rules::compile_files(files, set.detection_report);
    std::error_code ec;
    if (std::filesystem::is_regular_file(indicator_file, ec)) {
        set.indicators = yara::Rules::compile_files({indicator_file}, set.indicator_report);
    } else {
        set.indicator_report.errors.push_back("arquivo de indicadores ausente");
    }
    return set;
}

Output analyze(ByteView data, const Subject& subject, const RuleSet& rules, const Options& options, CancelToken* cancel) {
    return Analyzer(rules, options, cancel).run(data, subject, true);
}

Output analyze_file(const std::filesystem::path& path, const RuleSet& rules, const Options& options, CancelToken* cancel) {
    const MappedFile file = MappedFile::open(path);
    Subject s;
    const auto u8 = path.u8string();
    s.path = std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
    const auto name = path.filename().u8string();
    s.name = std::string(reinterpret_cast<const char*>(name.data()), name.size());
    const auto dir = path.parent_path().u8string();
    s.directory = std::string(reinterpret_cast<const char*>(dir.data()), dir.size());
    return analyze(file.view(), s, rules, options, cancel);
}

}  // namespace gk::analysis
