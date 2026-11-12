// Folder context (cracks, unlockers, mods, repacks) and the risk engine.
//
// The risk engine never invents probabilities. It applies explicit, explainable rules:
//   1. context mitigation lowers only traits *expected* for a recognised component (packing, DLL proxy,
//      anti-debugging...) — never signature, YARA, reputation or behavioural evidence;
//   2. the risk level is the highest effective severity;
//   3. the classification follows the strongest kind of evidence (signature/YARA verdict/reputation first);
//   4. every decision is written to `explanation` in plain Portuguese.
#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "gk/model.hpp"

namespace gk::risk {

struct Component {
    std::string id, name, kind, description;   // kind: crack | unlocker | mod | repack
    std::vector<std::string> evidence_dirs, evidence_files, evidence_patterns, version_markers, targets;
    std::map<std::string, std::string> content_labels;
};

struct ComponentDb {
    std::string version;
    std::vector<Component> components;
    static ComponentDb load(const std::filesystem::path& file);   // throws gk::Error on invalid data
};

struct CatalogEntry {
    std::string label;
    std::vector<std::string> recommendations;
};

struct Catalog {
    std::map<std::string, CatalogEntry> categories;
    std::map<std::string, std::string> risk_meaning;     // "HIGH" -> meaning
    std::map<std::string, std::string> classification_label;
    std::map<std::string, std::string> source_label;
    static Catalog load(const std::filesystem::path& file);
};

struct FileContext {
    std::string family_id, family_name, family_kind;     // empty when not part of a recognised component
    bool crack_like = false;                             // naming/folder/unlocker patterns
    bool modified = false;                               // replaced or proxy DLL without recognised component
    std::vector<Evidence> evidences;                     // context evidence to attach
};

// Folder-level correlation over every result of a scan (top-level files and archive members).
std::vector<FileContext> derive_context(const std::vector<FileResult>& files, const ComponentDb& db);

// Apply context + rules to one result (fills risk, classification, crack_status, primary_category,
// possible_false_positive, explanation, recommendations; adjusts evidence severities).
void assess(FileResult& result, const FileContext& context, const Catalog& catalog);

// Convenience: derive context for all results and assess each of them.
void assess_all(std::vector<FileResult>& files, const ComponentDb& db, const Catalog& catalog);

// Glob matching used by the component database (case-insensitive, '*' and '?').
bool glob_match(std::string_view pattern, std::string_view text);

}  // namespace gk::risk
