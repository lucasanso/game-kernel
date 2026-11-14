// Evidence from Authenticode signatures (structure everywhere; trust on Windows). See docs/DETECTION_RULES.md.
//
// Policy: a valid signature never lowers the risk of other findings (stolen certificates exist and revocation
// cannot be checked offline); it is reported as information. Broken, untrusted or distrusted signatures are
// evidence with the severity below.
#include <algorithm>
#include <array>
#include <cctype>

#include "evidence_util.hpp"
#include "gk/analysis.hpp"

namespace gk::analysis {

using detail::loc;
using detail::make;

namespace {

Location table_location(const authenticode::Report& r) {
    Location l = loc("certificate", "tabela de certificados (assinatura digital)");
    l.offset = r.table_offset;
    l.length = r.table_size;
    return l;
}

const authenticode::Signature* primary(const authenticode::Report& r) {
    return r.signatures.empty() ? nullptr : &r.signatures.front();
}

std::string claimed_signer(const authenticode::Report& r) {
    const auto* s = primary(r);
    if (s == nullptr || !s->signer) return {};
    return !s->signer->subject_cn.empty() ? s->signer->subject_cn : s->signer->subject_o;
}

void add_signature_details(const authenticode::Report& r, Evidence& e) {
    if (const auto* s = primary(r)) {
        e.details["algoritmo"] = s->digest_algorithm;
        e.details["resumo_assinado"] = s->signed_digest;
        if (s->image_digest) e.details["resumo_calculado"] = *s->image_digest;
        if (s->signer) {
            e.details["assinante_declarado"] = s->signer->subject_cn;
            if (!s->signer->subject_o.empty()) e.details["organizacao_declarada"] = s->signer->subject_o;
            e.details["emissor_declarado"] = s->signer->issuer_cn;
            e.details["certificado_sha256"] = s->signer->sha256;
            if (!s->signer->not_after.empty()) e.details["valido_ate"] = s->signer->not_after;
            if (s->signer->self_issued) e.details["autoemitido"] = "sim";
        }
        e.details["carimbo_de_tempo"] = s->timestamped ? "sim" : "não";
    }
    if (r.signatures.size() > 1) e.details["assinaturas"] = std::to_string(r.signatures.size());
    for (std::size_t i = 0; i < r.anomalies.size() && i < 4; ++i) e.details["anomalia_" + std::to_string(i + 1)] = r.anomalies[i];
}

bool has(const std::vector<Evidence>& out, std::string_view rule) {
    return std::any_of(out.begin(), out.end(), [&](const Evidence& e) { return e.rule_id == rule; });
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Publishers whose names a self-signed certificate should never carry.
constexpr std::array<std::string_view, 11> kWellKnownPublishers = {
    "microsoft", "valve", "nvidia", "intel", "advanced micro devices", "epic games",
    "electronic arts", "ubisoft", "rockstar games", "google", "activision"};

// Whole-word match in lower-case text ("intel" matches "Intel Corporation", not "Intellisoft").
bool contains_word(const std::string& text, std::string_view word) {
    auto alnum = [](char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; };
    for (std::size_t at = text.find(word); at != std::string::npos; at = text.find(word, at + 1)) {
        const bool left = at == 0 || !alnum(text[at - 1]);
        const bool right = at + word.size() >= text.size() || !alnum(text[at + word.size()]);
        if (left && right) return true;
    }
    return false;
}

}  // namespace

void signature_evidence(const authenticode::Report& r, std::vector<Evidence>& out, FileFeatures& features) {
    if (!r.present) return;
    features.signed_ = true;
    if (r.error && !r.parsed()) {
        features.signature_valid = false;
        Evidence e = make("PE.Signature.Malformed", "Assinatura digital corrompida ou malformada", Source::Static,
                          category::kStructural, Risk::Low, Confidence::High,
                          "O arquivo declara uma assinatura digital, mas ela não pôde ser lida (" + *r.error +
                              "). Para o Windows, o arquivo não tem assinatura válida.",
                          "Downloads incompletos e editores de recursos podem corromper a assinatura sem intenção maliciosa.");
        e.locations.push_back(table_location(r));
        out.push_back(std::move(e));
        return;
    }
    if (r.tampered()) {
        features.signature_valid = false;
        const std::string signer = claimed_signer(r);
        Evidence e = make("PE.Signature.Tampered", "Arquivo alterado depois de assinado", Source::Static,
                          category::kStructural, Risk::Low, Confidence::High,
                          "O arquivo traz uma assinatura digital" + (signer.empty() ? std::string() : " (declarada por \"" + signer + "\")") +
                              ", mas o conteúdo atual não corresponde ao resumo que foi assinado: ele foi modificado depois da "
                              "assinatura — por um crack, patch, unpacker, corrupção ou adulteração.",
                          "Cracks, patches e ferramentas como o Steamless alteram executáveis assinados; isso sozinho não "
                          "indica malware, mas significa que o arquivo não é mais o original do fabricante.");
        e.locations.push_back(table_location(r));
        add_signature_details(r, e);
        out.push_back(std::move(e));
    } else if (r.parsed()) {
        Evidence e = make("PE.Signature.Present", "Assinatura digital embutida", Source::Static,
                          category::kInformational, Risk::Info, Confidence::Medium,
                          "Assinatura digital declarada por \"" + claimed_signer(r) +
                              "\"; o conteúdo corresponde ao resumo assinado. Sem a verificação da cadeia de certificados "
                              "(feita pelo Windows), o nome do assinante é apenas declarado.");
        e.locations.push_back(table_location(r));
        add_signature_details(r, e);
        out.push_back(std::move(e));
    }
    if (r.hidden_bytes > 0) {
        Evidence e = make("PE.Signature.HiddenData", "Dados escondidos fora da área assinada", Source::Static,
                          category::kStructural, Risk::Low, Confidence::High,
                          std::to_string(r.hidden_bytes) +
                              " bytes não nulos foram acrescentados depois dos dados da assinatura. Essa região não é coberta "
                              "pela assinatura e já foi usada para esconder cargas em instaladores assinados (CVE-2013-3900).",
                          "Alguns instaladores legítimos gravam ali identificadores de download ou de campanha.");
        e.locations.push_back(table_location(r));
        out.push_back(std::move(e));
    }
}

void trust_evidence(const authenticode::TrustResult& t, const authenticode::Report& structure,
                    std::vector<Evidence>& out, FileFeatures& features) {
    using authenticode::TrustState;
    if (t.state == TrustState::NotChecked) return;
    // The structural "present" note is superseded by the trust verdict.
    out.erase(std::remove_if(out.begin(), out.end(), [](const Evidence& e) { return e.rule_id == "PE.Signature.Present"; }),
              out.end());

    auto add = [&](std::string rule, std::string title, std::string_view cat, Risk sev, Confidence conf,
                   std::string fp = {}) {
        Evidence e = make(std::move(rule), std::move(title), Source::Static, cat, sev, conf, t.message, std::move(fp),
                          "authenticode");
        if (structure.present) e.locations.push_back(table_location(structure));
        add_signature_details(structure, e);
        e.details["estado_windows"] = std::string(authenticode::value_of(t.state));
        e.details["codigo_windows"] = "0x" + [&] {
            static constexpr char kHex[] = "0123456789ABCDEF";
            std::string h(8, '0');
            for (int i = 0; i < 8; ++i) h[static_cast<std::size_t>(7 - i)] = kHex[(t.status_code >> (4 * i)) & 0xFU];
            return h;
        }();
        if (!t.signer.empty()) e.details["assinante"] = t.signer;
        if (!t.issuer.empty()) e.details["emissor"] = t.issuer;
        if (!t.signer_thumbprint.empty()) e.details["certificado_sha256"] = t.signer_thumbprint;
        if (!t.timestamp.empty()) e.details["carimbo_de_tempo"] = t.timestamp;
        if (t.from_catalog) e.details["catalogo"] = t.catalog;
        out.push_back(std::move(e));
    };

    switch (t.state) {
        case TrustState::Trusted:
            features.signed_ = true;
            features.signature_valid = true;
            features.signer = t.signer;
            add("PE.Signature.Trusted", "Assinatura digital válida", category::kInformational, Risk::Info, Confidence::High);
            break;
        case TrustState::Unsigned:
            break;
        case TrustState::BadDigest:
            features.signed_ = true;
            features.signature_valid = false;
            if (!has(out, "PE.Signature.Tampered")) {
                add("PE.Signature.Tampered", "Arquivo alterado depois de assinado", category::kStructural, Risk::Low,
                    Confidence::High, "Cracks, patches e unpackers alteram executáveis assinados; isso sozinho não indica malware.");
            }
            break;
        case TrustState::UntrustedRoot:
        case TrustState::Invalid: {
            features.signed_ = true;
            features.signature_valid = false;
            const bool untrusted = t.state == TrustState::UntrustedRoot;
            add(untrusted ? "PE.Signature.UntrustedRoot" : "PE.Signature.Invalid",
                untrusted ? "Assinatura com certificado não confiável" : "Assinatura digital inválida", category::kStructural,
                Risk::Low, Confidence::High,
                untrusted ? "Desenvolvedores independentes e ferramentas de mod às vezes usam certificados próprios." : "");
            const std::string claimed = lower(claimed_signer(structure) + " " +
                                              (primary(structure) && primary(structure)->signer
                                                   ? primary(structure)->signer->subject_o
                                                   : std::string()));
            for (auto publisher : kWellKnownPublishers) {
                if (!contains_word(claimed, publisher)) continue;
                Evidence e = make("PE.Signature.SpoofedPublisher", "Assinatura imita uma empresa conhecida",
                                  Source::Static, category::kDefenseEvasion, Risk::Medium, Confidence::High,
                                  "O certificado declara o nome \"" + claimed_signer(structure) +
                                      "\", mas não é confiável para o Windows: alguém criou um certificado com o nome de "
                                      "uma empresa conhecida para parecer legítimo.",
                                  "Builds de teste internas raramente chegam ao usuário final.", "authenticode");
                if (structure.present) e.locations.push_back(table_location(structure));
                add_signature_details(structure, e);
                out.push_back(std::move(e));
                break;
            }
            break;
        }
        case TrustState::Expired:
            features.signed_ = true;
            features.signature_valid = false;
            add("PE.Signature.Expired", "Certificado expirado sem carimbo de tempo", category::kInformational, Risk::Info,
                Confidence::High, "Software antigo costuma ter assinaturas expiradas; isso não indica ameaça.");
            break;
        case TrustState::Revoked:
        case TrustState::Distrusted:
            features.signed_ = true;
            features.signature_valid = false;
            add(t.state == TrustState::Revoked ? "PE.Signature.Revoked" : "PE.Signature.Distrusted",
                t.state == TrustState::Revoked ? "Certificado de assinatura revogado" : "Certificado bloqueado pelo Windows",
                category::kDefenseEvasion, Risk::High, Confidence::High,
                "Certificados são revogados ou bloqueados principalmente depois de roubados ou usados para assinar malware.");
            break;
        case TrustState::ChainIncomplete:
            features.signed_ = true;
            add("PE.Signature.Unverified", "Assinatura não confirmada offline", category::kInformational, Risk::Info,
                Confidence::Medium, "Falta um certificado intermediário no computador; isso é comum e não indica ameaça.");
            break;
        case TrustState::NotChecked:
            break;
    }
}

}  // namespace gk::analysis
