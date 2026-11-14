#include "gk/scan_support.hpp"

namespace gk::scan {

std::map<std::string, std::string> parse_clamscan(const std::string& output) {
    std::map<std::string, std::string> hits;
    std::size_t start = 0;
    while (start < output.size()) {
        std::size_t end = output.find('\n', start);
        if (end == std::string::npos) end = output.size();
        std::string line = output.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        static constexpr std::string_view kFound = " FOUND";
        if (line.size() > kFound.size() && line.compare(line.size() - kFound.size(), kFound.size(), kFound) == 0) {
            // The path may contain ": " — the signature is after the LAST ": ".
            const std::string body = line.substr(0, line.size() - kFound.size());
            const auto sep = body.rfind(": ");
            if (sep != std::string::npos) hits[body.substr(0, sep)] = body.substr(sep + 2);
        }
        start = end + 1;
    }
    return hits;
}

Evidence clamav_evidence(const std::string& signature, bool inside_archive) {
    Evidence e;
    e.rule_id = "CLAMAV." + signature;
    e.source = Source::Signature;
    e.engine = "clamav";
    e.confidence = Confidence::High;
    e.details["signature"] = signature;
    const std::string lower = lower_ascii(signature);
    Location l;
    l.kind = inside_archive ? "member" : "header";
    l.description = inside_archive ? "detectado pelo ClamAV dentro do conteúdo compactado" : "arquivo inteiro";
    e.locations.push_back(l);
    if (lower.find("eicar") != std::string::npos || lower.rfind("gamekernel.test", 0) == 0) {
        e.title = "Arquivo de teste antivírus (" + signature + ")";
        e.category = std::string(category::kTestFile);
        e.severity = Risk::High;
        e.details["verdict"] = "test";
        e.description = "O ClamAV reconheceu o arquivo de teste EICAR, que é inofensivo.";
    } else if (lower.rfind("pua.", 0) == 0 || lower.find(".pua.") != std::string::npos) {
        e.title = "Programa potencialmente indesejado: " + signature;
        e.category = std::string(category::kPua);
        e.severity = Risk::Medium;
        e.details["verdict"] = "pua";
        e.description = "Assinatura PUA do ClamAV (ferramentas como keygens, patchers e adware).";
        e.fp_note = "Keygens e patchers são classificados como PUA por natureza, mesmo sem carga maliciosa.";
    } else if (lower.rfind("heuristics.", 0) == 0) {
        e.source = Source::Heuristic;
        e.title = "Heurística do ClamAV: " + signature;
        e.category = lower.find("encrypted") != std::string::npos ? std::string(category::kStealth)
                                                                    : std::string(category::kStructural);
        e.severity = Risk::Medium;
        e.confidence = Confidence::Medium;
        e.details["verdict"] = "suspicious";
        e.description = "Alerta heurístico do ClamAV (estrutura incomum, conteúdo cifrado ou formato quebrado).";
        e.fp_note = "Alertas heurísticos não identificam uma família de malware.";
    } else {
        e.title = "Malware detectado pelo ClamAV: " + signature;
        e.category = std::string(category::kGenericMalware);
        if (lower.find("ransom") != std::string::npos) e.category = std::string(category::kRansomware);
        else if (lower.find("coinminer") != std::string::npos || lower.find("miner") != std::string::npos) e.category = std::string(category::kCryptominer);
        else if (lower.find("trojan") != std::string::npos) e.category = std::string(category::kTrojan);
        else if (lower.find("rat") != std::string::npos && lower.find(".rat") != std::string::npos) e.category = std::string(category::kRat);
        else if (lower.find("keylog") != std::string::npos) e.category = std::string(category::kKeylogger);
        else if (lower.find("downloader") != std::string::npos) e.category = std::string(category::kDownloader);
        e.severity = Risk::Critical;
        e.details["verdict"] = "malware";
        e.description = "Assinatura do ClamAV para ameaça conhecida.";
        e.fp_note = "Assinaturas genéricas raramente geram falsos positivos; se for o caso, marque o arquivo como confiável.";
    }
    return e;
}

}  // namespace gk::scan
