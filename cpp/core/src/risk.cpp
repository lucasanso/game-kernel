#include "gk/risk.hpp"

#include <algorithm>
#include <fstream>
#include <set>
#include <sstream>

#include <nlohmann/json.hpp>

#include "gk/error.hpp"
#include "gk/file_view.hpp"
#include "gk/filetype.hpp"

namespace gk::risk {

namespace {

using nlohmann::json;
using namespace std::string_view_literals;

json read_json(const std::filesystem::path& file) {
    ReadOnlyFile f = ReadOnlyFile::open(file);
    if (f.size() > (16u << 20)) throw Error(ErrorCode::ResourceLimit, "arquivo de dados grande demais");
    std::string text(static_cast<std::size_t>(f.size()), '\0');
    std::size_t done = 0;
    while (done < text.size()) {
        const std::size_t got = f.read(reinterpret_cast<std::uint8_t*>(text.data()) + done, text.size() - done);
        if (got == 0) break;
        done += got;
    }
    text.resize(done);
    try {
        return json::parse(text);
    } catch (const json::exception& e) {
        throw Error(ErrorCode::InvalidFormat, std::string("JSON inválido: ") + e.what());
    }
}

std::vector<std::string> str_list(const json& j, const char* key) {
    std::vector<std::string> out;
    if (j.contains(key) && j[key].is_array()) {
        for (const auto& v : j[key]) {
            if (v.is_string()) out.push_back(v.get<std::string>());
        }
    }
    return out;
}

std::string norm(std::string p) {
    std::replace(p.begin(), p.end(), '\\', '/');
    return lower_ascii(p);
}

// Folder of a result: physical directory, or the container chain up to the member's parent.
std::string folder_of(const FileResult& r) {
    std::string p = norm(r.path);
    const auto sep = p.find_last_of('/');
    const auto chain = p.rfind("::");
    if (chain != std::string::npos && (sep == std::string::npos || sep < chain)) return p.substr(0, chain);
    return sep == std::string::npos ? std::string() : p.substr(0, sep);
}

bool is_code(const FileResult& r) {
    const std::string ext = lower_ascii(r.extension);
    return r.features.is_pe || r.file_type.rfind("pe_", 0) == 0 || r.file_type == "msdos" || ext == ".exe" ||
           ext == ".dll" || ext == ".asi" || ext == ".sys";
}

const std::set<std::string_view> kExpectedForComponent = {
    "PE.MinimalImports", "PE.HighEntropyCode", "PE.WriteExecuteSection", "PE.EntryPoint.Unusual",
    "PE.TlsCallbacks",   "PE.DllProxy",        "HEUR.AntiAnalysis",      "PE.DRM.SteamStub",
    "PE.Signature.Tampered"};

bool expected_trait(const Evidence& e, const std::string& kind) {
    if (e.source == Source::Signature || e.source == Source::Yara || e.source == Source::Reputation ||
        e.source == Source::Behavioral) {
        return false;
    }
    if (kExpectedForComponent.count(e.rule_id) || e.rule_id.rfind("PE.Packer.", 0) == 0 ||
        e.rule_id.rfind("PE.Overlay.", 0) == 0) {
        return true;
    }
    if (kind == "mod" && e.rule_id == "HEUR.Injection.RemoteThread") return true;
    if (kind == "repack" && (e.rule_id == "PE.EmbeddedExecutable.Resource" || e.rule_id == "PE.RequiresAdmin")) return true;
    return false;
}

std::string verdict_of(const Evidence& e) {
    auto it = e.details.find("verdict");
    return it == e.details.end() ? std::string() : lower_ascii(it->second);
}

int source_rank(Source s) {
    switch (s) {
        case Source::Signature: return 7;
        case Source::Reputation: return 6;
        case Source::Yara: return 5;
        case Source::Behavioral: return 4;
        case Source::Heuristic: return 3;
        case Source::Static: return 2;
        case Source::Context: return 1;
    }
    return 0;
}

Evidence context_evidence(std::string rule, std::string title, std::string_view category, Risk sev,
                          std::string description, std::string fp = {}) {
    Evidence e;
    e.rule_id = std::move(rule);
    e.title = std::move(title);
    e.source = Source::Context;
    e.category = std::string(category);
    e.severity = sev;
    e.confidence = Confidence::Medium;
    e.description = std::move(description);
    e.fp_note = std::move(fp);
    e.engine = "game_context";
    return e;
}

}  // namespace

bool glob_match(std::string_view pattern, std::string_view text) {
    // Iterative matcher with backtracking on the last '*'; ASCII case-insensitive.
    std::size_t p = 0, t = 0, star = std::string_view::npos, mark = 0;
    auto eq = [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    };
    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || eq(pattern[p], text[t]))) {
            ++p;
            ++t;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            mark = t;
        } else if (star != std::string_view::npos) {
            p = star + 1;
            t = ++mark;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

ComponentDb ComponentDb::load(const std::filesystem::path& file) {
    const json j = read_json(file);
    if (j.value("format", "") != "gamekernel-components") throw Error(ErrorCode::InvalidFormat, "formato de componentes inválido");
    ComponentDb db;
    db.version = j.value("version", "");
    const json components = j.value("components", json::array());
    for (const auto& c : components) {
        Component comp;
        comp.id = c.value("id", "");
        comp.name = c.value("name", comp.id);
        comp.kind = c.value("kind", "crack");
        comp.description = c.value("description", "");
        if (c.contains("evidence")) {
            comp.evidence_dirs = str_list(c["evidence"], "dirs");
            comp.evidence_files = str_list(c["evidence"], "files");
            comp.evidence_patterns = str_list(c["evidence"], "patterns");
        }
        comp.version_markers = str_list(c, "version_markers");
        comp.targets = str_list(c, "targets");
        if (c.contains("content_labels") && c["content_labels"].is_object()) {
            for (const auto& [k, v] : c["content_labels"].items()) comp.content_labels[k] = v.get<std::string>();
        }
        if (comp.id.empty()) throw Error(ErrorCode::InvalidFormat, "componente sem id");
        db.components.push_back(std::move(comp));
    }
    return db;
}

Catalog Catalog::load(const std::filesystem::path& file) {
    const json j = read_json(file);
    if (j.value("format", "") != "gamekernel-threat-catalog") throw Error(ErrorCode::InvalidFormat, "catálogo inválido");
    Catalog c;
    // Bind each section to a named value: iterating items() of a temporary would dangle (C++20 range-for).
    const json categories = j.value("categories", json::object());
    const json levels = j.value("risk_levels", json::object());
    const json classes = j.value("classifications", json::object());
    const json sources = j.value("evidence_sources", json::object());
    for (const auto& [k, v] : categories.items()) c.categories[k] = CatalogEntry{v.value("label", k), str_list(v, "recommendations")};
    for (const auto& [k, v] : levels.items()) c.risk_meaning[k] = v.value("meaning", "");
    for (const auto& [k, v] : classes.items()) c.classification_label[k] = v.get<std::string>();
    for (const auto& [k, v] : sources.items()) c.source_label[k] = v.get<std::string>();
    return c;
}

std::vector<FileContext> derive_context(const std::vector<FileResult>& files, const ComponentDb& db) {
    std::vector<FileContext> ctx(files.size());
    std::map<std::string, std::vector<std::size_t>> by_folder;
    std::set<std::string> directories;
    for (std::size_t i = 0; i < files.size(); ++i) {
        const std::string folder = folder_of(files[i]);
        by_folder[folder].push_back(i);
        // every ancestor directory (so "<folder>/steam_settings" exists when a file lives below it)
        std::string d = folder;
        while (!d.empty()) {
            directories.insert(d);
            const auto cut = d.find_last_of('/');
            if (cut == std::string::npos) break;
            d.resize(cut);
        }
    }

    // Deliberately specific: "patch" and "loader" also name official updaters and mod loaders.
    static constexpr std::string_view kCrackTokens[] = {"crack", "keygen", "trainer", "unlocker", "nodvd", "no-dvd",
                                                        "activator", "kmsauto", "kms_auto"};
    static constexpr std::string_view kCrackFolders[] = {"crack", "cracked", "crackfix", "keygen", "codex", "plaza",
                                                         "skidrow", "reloaded", "rune", "empress", "tenoke", "cpy",
                                                         "flt", "dodi", "nodvd"};

    for (const auto& [folder, members] : by_folder) {
        std::map<std::string, std::size_t> names;  // lower name -> index
        for (std::size_t i : members) names[lower_ascii(files[i].name)] = i;

        for (const Component& comp : db.components) {
            bool matched = false;
            std::string label = comp.name;
            for (const auto& f : comp.evidence_files) {
                auto it = names.find(lower_ascii(f));
                if (it == names.end()) continue;
                matched = true;
                const auto& head = files[it->second].features.text_head;
                for (const auto& [marker, group] : comp.content_labels) {
                    if (head && lower_ascii(*head).find(lower_ascii(marker)) != std::string::npos) {
                        label = comp.name + " — " + group;
                        break;
                    }
                }
            }
            for (const auto& d : comp.evidence_dirs) {
                if (directories.count(folder.empty() ? lower_ascii(d) : folder + "/" + lower_ascii(d))) matched = true;
            }
            for (const auto& pattern : comp.evidence_patterns) {
                for (const auto& [name, _] : names) {
                    if (glob_match(pattern, name)) matched = true;
                }
            }
            for (std::size_t i : members) {
                const FileResult& r = files[i];
                bool by_marker = false;
                for (const auto& marker : comp.version_markers) {
                    for (const auto& [key, value] : r.features.version_info) {
                        if (lower_ascii(value).find(lower_ascii(marker)) != std::string::npos) by_marker = true;
                    }
                }
                bool is_target = false;
                if (matched || by_marker) {
                    for (const auto& t : comp.targets) {
                        if (glob_match(t, r.name)) is_target = true;
                    }
                    for (const auto& f : comp.evidence_files) {
                        if (lower_ascii(f) == lower_ascii(r.name)) is_target = true;
                    }
                }
                if (!(by_marker || (matched && is_target))) continue;
                FileContext& c = ctx[i];
                if (!c.family_id.empty()) continue;
                c.family_id = comp.id;
                c.family_name = label;
                c.family_kind = comp.kind;
                const std::string_view cat = comp.kind == "mod" ? category::kModComponent
                                             : comp.kind == "repack" ? category::kInformational
                                                                     : category::kCrackComponent;
                c.evidences.push_back(context_evidence(
                    "CONTEXT.Component." + comp.id, "Componente reconhecido: " + label, cat, Risk::Info,
                    comp.description + " Reconhecer o componente não garante que esta cópia seja segura: as demais "
                                       "evidências continuam valendo."));
            }
        }

        for (std::size_t i : members) {
            const FileResult& r = files[i];
            FileContext& c = ctx[i];
            const std::string lname = lower_ascii(r.name);
            if (is_code(r)) {
                for (auto token : kCrackTokens) {
                    if (lname.find(token) == std::string::npos) continue;
                    c.crack_like = true;
                    c.evidences.push_back(context_evidence(
                        "CONTEXT.CrackLikeName", "Nome sugere crack, keygen, patch ou trainer", category::kCrackComponent,
                        Risk::Info, "O nome \"" + r.name + "\" indica uma ferramenta para contornar proteção ou alterar o jogo.",
                        "Nomes podem ser enganosos; a análise de ameaças continua aplicada."));
                    break;
                }
                std::string segments = "/" + folder + "/";
                for (auto f : kCrackFolders) {
                    if (segments.find("/" + std::string(f) + "/") == std::string::npos) continue;
                    c.crack_like = true;
                    c.evidences.push_back(context_evidence(
                        "CONTEXT.CrackFolder", "Arquivo em pasta de crack", category::kCrackComponent, Risk::Info,
                        "O arquivo está numa pasta chamada \"" + std::string(f) + "\", usada para distribuir cracks.",
                        "O nome da pasta foi escolhido por quem empacotou o jogo."));
                    break;
                }
            }
            // Original DLL kept with "_o" suffix: replaced DLL (DLC unlockers, proxies).
            if (lname.size() > 4 && lname.substr(lname.size() - 4) == ".dll") {
                const std::string original = lname.substr(0, lname.size() - 4) + "_o.dll";
                if (names.count(original)) {
                    c.modified = true;
                    c.evidences.push_back(context_evidence(
                        "CONTEXT.ReplacedDll", "DLL substituída (original renomeada para " + files[names[original]].name + ")",
                        category::kCrackComponent, c.family_id.empty() ? Risk::Low : Risk::Info,
                        "Esta DLL ocupa o lugar da original, que foi mantida com o sufixo _o — padrão de desbloqueadores "
                        "de DLC e proxies.",
                        "Desbloqueadores de DLC conhecidos usam exatamente este padrão."));
                }
            }
            const bool proxy = std::any_of(r.evidences.begin(), r.evidences.end(),
                                           [](const Evidence& e) { return e.rule_id == "PE.DllProxy"; });
            // A signed file whose content no longer matches its signature was modified after the vendor built it.
            if (std::any_of(r.evidences.begin(), r.evidences.end(),
                            [](const Evidence& e) { return e.rule_id == "PE.Signature.Tampered"; })) {
                c.modified = true;
            }
            if (proxy && c.family_id.empty()) {
                c.modified = true;
                c.evidences.push_back(context_evidence(
                    "CONTEXT.UnrecognizedProxy", "Proxy de DLL não reconhecido", category::kDllHijacking, Risk::Low,
                    "Esta DLL substitui uma biblioteca do Windows e não corresponde a nenhum mod/crack conhecido. "
                    "Confirme se você instalou este componente.",
                    "Mods novos ou pouco conhecidos ainda não estão no banco de componentes."));
            }
        }
    }
    return ctx;
}

void assess(FileResult& r, const FileContext& ctx, const Catalog& catalog) {
    for (const auto& e : ctx.evidences) {
        const bool present = std::any_of(r.evidences.begin(), r.evidences.end(),
                                         [&](const Evidence& x) { return x.rule_id == e.rule_id; });
        if (!present) r.evidences.push_back(e);
    }
    // 1. Context mitigation of expected traits.
    std::size_t mitigated = 0;
    for (auto& e : r.evidences) {
        e.adjusted_severity.reset();
        e.adjustment_reason.clear();
        if (!ctx.family_id.empty() && expected_trait(e, ctx.family_kind) && e.severity > Risk::Info) {
            e.adjusted_severity = Risk::Info;
            e.adjustment_reason = "característica esperada em " + ctx.family_name;
            ++mitigated;
        } else if (ctx.family_id.empty() && ctx.crack_like && expected_trait(e, "crack") && e.severity > Risk::Info) {
            e.adjusted_severity = lower(e.severity, 1);
            e.adjustment_reason = "característica comum em cracks (componente não reconhecido)";
            ++mitigated;
        }
    }

    // 2. Risk level.
    Risk risk = Risk::None;
    for (const auto& e : r.evidences) risk = std::max(risk, e.effective());

    // 3. Classification.
    bool malware = false, pua = false, test_file = false, good_reputation = false;
    for (const auto& e : r.evidences) {
        const std::string verdict = verdict_of(e);
        if (e.source == Source::Signature || e.source == Source::Reputation) {
            if (verdict == "pua") {
                pua = true;
            } else if (verdict == "good" || verdict == "known_good") {
                good_reputation = true;
            } else if (verdict == "test") {
                malware = test_file = true;
            } else {
                malware = true;
            }
        } else if (e.source == Source::Yara) {
            if (verdict == "malware") malware = true;
            if (verdict == "test") malware = test_file = true;
            if (verdict == "pua") pua = true;
        } else if (e.source == Source::Behavioral && e.effective() >= Risk::Critical) {
            malware = true;
        }
    }
    const bool partial = r.status == AnalysisStatus::Partial || r.status == AnalysisStatus::Error ||
                         r.status == AnalysisStatus::Skipped;
    std::string why;
    if (malware) {
        r.classification = Classification::Malware;
        risk = std::max(risk, Risk::High);
        why = test_file ? "um arquivo de teste antivírus (inofensivo) foi identificado com certeza"
                        : "uma assinatura, regra de família ou indicador local identifica ameaça conhecida";
    } else if (pua) {
        r.classification = Classification::Pua;
        why = "uma assinatura ou regra classifica o arquivo como potencialmente indesejado";
    } else if (risk >= Risk::Medium) {
        r.classification = Classification::Suspicious;
        why = "há evidências estáticas/heurísticas de comportamento perigoso, sem assinatura de ameaça conhecida";
    } else if (partial && (is_code(r) || r.file_type == "zip" || r.file_type == "7z" || r.file_type == "rar") &&
               risk <= Risk::Low) {
        r.classification = Classification::Inconclusive;
        why = "a análise não pôde ser concluída (" +
              (r.status_reasons.empty() ? std::string("motivo não informado") : r.status_reasons.front()) + ")";
    } else if (ctx.modified || ctx.crack_like || !ctx.family_id.empty()) {
        r.classification = (ctx.family_kind == "mod" || ctx.family_kind == "repack") && !ctx.modified
                               ? Classification::Unknown
                               : Classification::Modified;
        const bool tampered = std::any_of(r.evidences.begin(), r.evidences.end(),
                                          [](const Evidence& e) { return e.rule_id == "PE.Signature.Tampered"; });
        why = r.classification != Classification::Modified
                  ? "componente de mod/instalador reconhecido, sem evidência de ameaça"
              : tampered && ctx.family_id.empty() && !ctx.crack_like
                  ? "o arquivo foi alterado depois de assinado pelo fabricante, sem evidência de ameaça"
                  : "o arquivo pertence a um crack, desbloqueador ou substitui um componente original, sem evidência de ameaça";
    } else if (good_reputation) {
        r.classification = Classification::KnownLegit;
        why = "o hash consta na base local de arquivos conhecidos como legítimos";
    } else {
        r.classification = Classification::Unknown;
        why = "nenhum mecanismo encontrou evidência de ameaça; isso não prova que o arquivo é seguro";
    }
    r.risk = risk;

    // 4. Crack status.
    const bool crack_context = (!ctx.family_id.empty() && ctx.family_kind != "mod" && ctx.family_kind != "repack") ||
                               ctx.crack_like || ctx.modified;
    if (!crack_context) {
        r.crack_status = CrackStatus::None;
    } else if (r.classification == Classification::Malware) {
        r.crack_status = CrackStatus::Malware;
    } else if (r.classification == Classification::Suspicious || r.classification == Classification::Pua) {
        r.crack_status = CrackStatus::Suspicious;
    } else if (r.classification == Classification::Inconclusive) {
        r.crack_status = CrackStatus::Insufficient;
    } else if (!ctx.family_id.empty()) {
        r.crack_status = CrackStatus::RecognizedClean;
    } else if (ctx.modified && !ctx.crack_like) {
        r.crack_status = CrackStatus::ModifiedNoThreat;
    } else {
        r.crack_status = CrackStatus::Unknown;
    }

    // 5. Primary category: strongest effective evidence, then strongest source.
    const Evidence* top = nullptr;
    for (const auto& e : r.evidences) {
        if (top == nullptr || e.effective() > top->effective() ||
            (e.effective() == top->effective() && source_rank(e.source) > source_rank(top->source))) {
            top = &e;
        }
    }
    r.primary_category = (top != nullptr && top->effective() > Risk::Info) ? std::optional<std::string>(top->category)
                                                                           : std::nullopt;

    // 6. Possible false positive: no signature/reputation/high-confidence YARA, only heuristics with FP notes.
    bool strong = false;
    for (const auto& e : r.evidences) {
        if (e.effective() < Risk::Medium) continue;
        if (e.source == Source::Signature || e.source == Source::Reputation || e.source == Source::Behavioral ||
            (e.source == Source::Yara && e.confidence == Confidence::High)) {
            strong = true;
        }
    }
    r.possible_false_positive =
        (r.classification == Classification::Suspicious || r.classification == Classification::Pua ||
         r.classification == Classification::Malware) && !strong;

    // 7. Explanation (ordered, plain language; no percentages).
    r.explanation.clear();
    const std::string level(name_of(risk));
    const auto meaning = catalog.risk_meaning.find(level);
    r.explanation.push_back("Nível de risco " + level + (meaning != catalog.risk_meaning.end() ? ": " + meaning->second : "."));
    const std::string cls(value_of(r.classification));
    const auto cls_label = catalog.classification_label.find(cls);
    r.explanation.push_back("Classificação \"" + (cls_label != catalog.classification_label.end() ? cls_label->second : cls) +
                            "\" porque " + why + ".");
    std::vector<const Evidence*> ranked;
    for (const auto& e : r.evidences) {
        if (e.effective() > Risk::Info) ranked.push_back(&e);
    }
    std::stable_sort(ranked.begin(), ranked.end(), [](const Evidence* a, const Evidence* b) {
        if (a->effective() != b->effective()) return a->effective() > b->effective();
        return source_rank(a->source) > source_rank(b->source);
    });
    for (std::size_t i = 0; i < ranked.size() && i < 5; ++i) {
        const Evidence& e = *ranked[i];
        const auto src = catalog.source_label.find(std::string(value_of(e.source)));
        r.explanation.push_back("Evidência: " + e.title + " — " +
                                (src != catalog.source_label.end() ? src->second : std::string(value_of(e.source))) +
                                ", severidade " + std::string(name_of(e.effective())) + ", confiança " +
                                std::string(name_of(e.confidence)) + ".");
    }
    if (r.features.signature_valid == true && r.features.signer && !r.features.signer->empty()) {
        r.explanation.push_back("Assinado digitalmente por " + *r.features.signer +
                                " (verificado pelo Windows, sem consulta à rede). Uma assinatura válida não reduz o risco "
                                "das demais evidências: certificados podem ser roubados.");
    }
    if (!ctx.family_id.empty()) {
        r.explanation.push_back("Componente reconhecido: " + ctx.family_name + "." +
                                (mitigated ? " " + std::to_string(mitigated) +
                                                 " característica(s) esperada(s) nesse tipo de componente foram "
                                                 "rebaixadas para Informativo."
                                           : std::string()));
    } else if (mitigated) {
        r.explanation.push_back(std::to_string(mitigated) +
                                " característica(s) comum(ns) em cracks tiveram a severidade reduzida em um nível.");
    }
    if (r.possible_false_positive) {
        std::string note;
        for (const Evidence* e : ranked) {
            if (!e->fp_note.empty()) {
                note = e->fp_note;
                break;
            }
        }
        r.explanation.push_back("Falso positivo possível: a conclusão vem de análise heurística/estática" +
                                (note.empty() ? std::string(".") : " — " + note));
    }

    // 8. Recommendations.
    r.recommendations.clear();
    if (r.primary_category) {
        auto it = catalog.categories.find(*r.primary_category);
        if (it != catalog.categories.end()) r.recommendations = it->second.recommendations;
    }
    switch (r.classification) {
        case Classification::Suspicious:
            r.recommendations.emplace_back("Não execute o arquivo até investigar as evidências; se precisar observar o "
                                           "comportamento, use a análise na sandbox isolada.");
            break;
        case Classification::Inconclusive:
            r.recommendations.emplace_back("A análise ficou incompleta: trate o arquivo como não verificado.");
            break;
        case Classification::Modified:
            r.recommendations.emplace_back("Arquivo alterado em relação ao original: confirme a origem antes de executar.");
            break;
        default:
            break;
    }
}

void assess_all(std::vector<FileResult>& files, const ComponentDb& db, const Catalog& catalog) {
    const std::vector<FileContext> contexts = derive_context(files, db);
    for (std::size_t i = 0; i < files.size(); ++i) assess(files[i], contexts[i], catalog);
}

}  // namespace gk::risk
