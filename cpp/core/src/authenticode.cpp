// Portable Authenticode inspection (structure + image hash). See gk/authenticode.hpp.
#include "gk/authenticode.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <variant>

#include "der.hpp"
#include "gk/error.hpp"
#include "gk/hash.hpp"
#include "gk/text.hpp"

namespace gk::authenticode {

namespace {

constexpr std::string_view kOidSignedData = "1.2.840.113549.1.7.2";
constexpr std::string_view kOidSpcIndirectData = "1.3.6.1.4.1.311.2.1.4";
constexpr std::string_view kOidNestedSignature = "1.3.6.1.4.1.311.2.4.1";
constexpr std::string_view kOidCounterSignature = "1.2.840.113549.1.9.6";
constexpr std::string_view kOidRfc3161Timestamp = "1.3.6.1.4.1.311.3.3.1";
constexpr std::string_view kOidCommonName = "2.5.4.3";
constexpr std::string_view kOidOrganization = "2.5.4.10";
constexpr std::uint16_t kWinCertRevision2 = 0x0200;
constexpr std::uint16_t kWinCertTypePkcsSignedData = 0x0002;

std::string algorithm_name(const std::string& oid) {
    if (oid == "1.2.840.113549.2.5") return "md5";
    if (oid == "1.3.14.3.2.26") return "sha1";
    if (oid == "2.16.840.1.101.3.4.2.1") return "sha256";
    if (oid == "2.16.840.1.101.3.4.2.2") return "sha384";
    if (oid == "2.16.840.1.101.3.4.2.3") return "sha512";
    return oid;
}

// ------------------------------------------------------------------ PE header locations

struct Range {
    std::size_t start = 0, size = 0;
};

struct Layout {
    Range checksum;
    std::optional<Range> cert_dir_entry;
    std::optional<Range> cert_table;          // only when its location is plausible (as Windows/signify)
    std::uint32_t declared_offset = 0, declared_size = 0;
};

// Mirrors the PE/COFF Authenticode specification ("Calculating the PE Image Hash").
std::optional<Layout> layout_of(ByteView f) {
    const auto lfanew = f.le<std::uint32_t>(0x3C);
    if (!f.starts_with("MZ") || !lfanew || !f.equals_at(*lfanew, std::string_view("PE\0\0", 4))) return std::nullopt;
    const std::size_t coff = static_cast<std::size_t>(*lfanew) + 4;
    const auto opt_size = f.le<std::uint16_t>(coff + 16);
    const std::size_t oh = coff + 20;
    const auto magic = f.le<std::uint16_t>(oh);
    if (!opt_size || !magic || (*magic != 0x10B && *magic != 0x20B) || !f.has(oh + 64, 4)) return std::nullopt;
    Layout l;
    l.checksum = {oh + 64, 4};
    const std::size_t rva_count_at = oh + (*magic == 0x20B ? 108 : 92);
    const std::size_t cert_at = oh + (*magic == 0x20B ? 144 : 128);
    const std::size_t opt_end = oh + *opt_size;
    if (opt_end < rva_count_at + 4) return l;
    const auto rva_count = f.le<std::uint32_t>(rva_count_at);
    if (!rva_count || *rva_count < 5 || opt_end < cert_at + 8) return l;
    const auto address = f.le<std::uint32_t>(cert_at);
    const auto size = f.le<std::uint32_t>(cert_at + 4);
    if (!address || !size) return l;
    l.cert_dir_entry = Range{cert_at, 8};
    l.declared_offset = *address;
    l.declared_size = *size;
    if (*size != 0 && *address >= opt_end && f.has(*address, *size)) l.cert_table = Range{*address, *size};
    return l;
}

// ------------------------------------------------------------------ hashing

class AnyHash {
public:
    static std::optional<AnyHash> make(const std::string& algorithm) {
        if (algorithm == "md5") return AnyHash(std::make_unique<Md5>());
        if (algorithm == "sha1") return AnyHash(std::make_unique<Sha1>());
        if (algorithm == "sha256") return AnyHash(std::make_unique<Sha256>());
        if (algorithm == "sha384") return AnyHash(std::make_unique<Sha512>(true));
        if (algorithm == "sha512") return AnyHash(std::make_unique<Sha512>(false));
        return std::nullopt;
    }
    void update(ByteView v) {
        std::visit([&](auto& h) { h->update(v); }, h_);
    }
    std::string finish() {
        return std::visit(
            [](auto& h) {
                const auto d = h->finish();
                return to_hex(std::span<const std::uint8_t>(d.data(), d.size()));
            },
            h_);
    }

private:
    using Variant = std::variant<std::unique_ptr<Md5>, std::unique_ptr<Sha1>, std::unique_ptr<Sha256>,
                                 std::unique_ptr<Sha512>>;
    template <typename T>
    explicit AnyHash(std::unique_ptr<T> h) : h_(std::move(h)) {}
    Variant h_;
};

std::optional<std::string> digest_with_layout(ByteView f, const Layout& l, const std::string& algorithm,
                                              CancelToken* cancel) {
    auto hasher = AnyHash::make(algorithm);
    if (!hasher) return std::nullopt;
    std::vector<Range> omit{l.checksum};
    if (l.cert_dir_entry) omit.push_back(*l.cert_dir_entry);
    if (l.cert_table) omit.push_back(*l.cert_table);
    std::sort(omit.begin(), omit.end(), [](const Range& a, const Range& b) { return a.start < b.start; });
    constexpr std::size_t kChunk = 1U << 20;
    auto feed = [&](std::size_t from, std::size_t to) {
        to = std::min(to, f.size());
        while (from < to) {
            if (cancel != nullptr && !cancel->wait_if_paused()) throw Error(ErrorCode::Cancelled, "análise cancelada");
            const std::size_t n = std::min(kChunk, to - from);
            hasher->update(f.clamp(from, n));
            from += n;
        }
    };
    std::size_t at = 0;
    for (const auto& r : omit) {
        if (r.start > at) feed(at, r.start);
        at = std::max(at, r.start + r.size);
    }
    feed(at, f.size());
    return hasher->finish();
}

// ------------------------------------------------------------------ X.509 / PKCS#7

// Raw UTF-8 of a directory string (unvalidated; callers pass it through text::display_utf8).
std::string string_value(const der::Element& e) {
    switch (e.tag) {
        case der::tag::kUtf8:
        case der::tag::kPrintable:
        case der::tag::kIa5:
            return e.content.prefix(4096).to_string();
        case der::tag::kT61: {
            std::string out;
            for (std::size_t i = 0; i < e.content.size(); ++i) text::append_utf8(out, *e.content.u8(i));
            return out;
        }
        case der::tag::kBmp: {
            std::string out;
            for (std::size_t i = 0; i + 1 < e.content.size(); i += 2) {
                text::append_utf8(out, (static_cast<std::uint32_t>(*e.content.u8(i)) << 8) | *e.content.u8(i + 1));
            }
            return out;
        }
        case der::tag::kUniversal: {
            std::string out;
            for (std::size_t i = 0; i + 3 < e.content.size(); i += 4) {
                const auto cp = (static_cast<std::uint32_t>(*e.content.u8(i)) << 24) |
                                (static_cast<std::uint32_t>(*e.content.u8(i + 1)) << 16) |
                                (static_cast<std::uint32_t>(*e.content.u8(i + 2)) << 8) | *e.content.u8(i + 3);
                text::append_utf8(out, cp <= 0x10FFFF ? cp : 0xFFFD);
            }
            return out;
        }
        default:
            return {};
    }
}

// Name ::= SEQUENCE OF RelativeDistinguishedName(SET OF AttributeTypeAndValue). Last CN/O wins, as most tools.
void read_name(ByteView name_content, std::string& cn, std::string& o) {
    der::Reader rdns(name_content);
    while (!rdns.at_end()) {
        der::Reader set(rdns.expect(der::tag::kSet, "nome").content);
        while (!set.at_end()) {
            der::Reader atv(set.expect(der::tag::kSequence, "atributo de nome").content);
            const std::string oid = der::oid_text(atv.expect(der::tag::kOid, "atributo de nome").content);
            const der::Element value = atv.next();
            // Names are attacker-controlled display text: decoded, then neutralised for display.
            if (oid == kOidCommonName) cn = text::display_utf8(string_value(value), 1024);
            if (oid == kOidOrganization) o = text::display_utf8(string_value(value), 1024);
        }
    }
}

std::string time_text(const der::Element& e) {
    const std::string s = e.content.to_string();
    std::string y, rest;
    if (e.tag == der::tag::kUtcTime && s.size() == 13 && s.back() == 'Z') {
        const int yy = (s[0] - '0') * 10 + (s[1] - '0');
        y = (yy < 50 ? "20" : "19") + s.substr(0, 2);
        rest = s.substr(2, 10);
    } else if (e.tag == der::tag::kGeneralizedTime && s.size() == 15 && s.back() == 'Z') {
        y = s.substr(0, 4);
        rest = s.substr(4, 10);
    } else {
        return {};
    }
    auto digits = [](const std::string& v) { return std::all_of(v.begin(), v.end(), [](char ch) { return ch >= '0' && ch <= '9'; }); };
    if (!digits(y) || !digits(rest)) return {};
    return y + "-" + rest.substr(0, 2) + "-" + rest.substr(2, 2) + "T" + rest.substr(4, 2) + ":" + rest.substr(6, 2) +
           ":" + rest.substr(8, 2) + "Z";
}

struct ParsedCertificate {
    Certificate info;
    ByteView issuer_der;
    ByteView serial_content;
};

ParsedCertificate parse_certificate(const der::Element& cert) {
    ParsedCertificate p;
    p.info.sha256 = sha256_hex(cert.encoded);
    der::Reader c(cert.content);
    der::Reader tbs(c.expect(der::tag::kSequence, "certificado").content);
    tbs.next_if(der::tag::context(0));
    p.serial_content = tbs.expect(der::tag::kInteger, "número de série").content;
    p.info.serial = to_hex(p.serial_content.span());
    tbs.expect(der::tag::kSequence, "algoritmo do certificado");
    const der::Element issuer = tbs.expect(der::tag::kSequence, "emissor");
    p.issuer_der = issuer.encoded;
    read_name(issuer.content, p.info.issuer_cn, p.info.issuer_o);
    der::Reader validity(tbs.expect(der::tag::kSequence, "validade").content);
    p.info.not_before = time_text(validity.next());
    p.info.not_after = time_text(validity.next());
    const der::Element subject = tbs.expect(der::tag::kSequence, "titular");
    read_name(subject.content, p.info.subject_cn, p.info.subject_o);
    p.info.self_issued = subject.encoded.size() == issuer.encoded.size() &&
                         std::equal(subject.encoded.data(), subject.encoded.data() + subject.encoded.size(),
                                    issuer.encoded.data());
    return p;
}

bool same_bytes(ByteView a, ByteView b) {
    return a.size() == b.size() && std::equal(a.data(), a.data() + a.size(), b.data());
}

struct Walker {
    ByteView file;
    const Layout& layout;
    const Limits& limits;
    CancelToken* cancel;
    Report& report;
    std::vector<Signature> nested;
    std::map<std::string, std::optional<std::string>> digests;   // one image pass per algorithm

    std::optional<std::string> digest(const std::string& algorithm) {
        auto it = digests.find(algorithm);
        if (it == digests.end()) it = digests.emplace(algorithm, digest_with_layout(file, layout, algorithm, cancel)).first;
        return it->second;
    }

    // ContentInfo(SignedData) → Signature; nested signatures are collected into `nested`.
    void parse_content_info(ByteView encoded, int depth) {
        if (report.signatures.size() + nested.size() >= limits.max_signatures) {
            report.anomalies.push_back("número de assinaturas acima do limite de análise");
            return;
        }
        der::Reader top(encoded);
        der::Reader ci(top.expect(der::tag::kSequence, "ContentInfo").content);
        if (der::oid_text(ci.expect(der::tag::kOid, "ContentInfo").content) != kOidSignedData) {
            der::Reader::fail("o conteúdo não é PKCS#7 SignedData");
        }
        der::Reader explicit_content(ci.expect(der::tag::context(0), "ContentInfo").content);
        der::Reader sd(explicit_content.expect(der::tag::kSequence, "SignedData").content);
        sd.expect(der::tag::kInteger, "versão do SignedData");
        sd.expect(der::tag::kSet, "algoritmos do SignedData");

        Signature sig;
        sig.depth = depth;
        der::Reader encap(sd.expect(der::tag::kSequence, "conteúdo assinado").content);
        if (der::oid_text(encap.expect(der::tag::kOid, "conteúdo assinado").content) != kOidSpcIndirectData) {
            der::Reader::fail("o conteúdo assinado não é SpcIndirectDataContent");
        }
        der::Reader encap_explicit(encap.expect(der::tag::context(0), "conteúdo assinado").content);
        der::Reader spc(encap_explicit.expect(der::tag::kSequence, "SpcIndirectDataContent").content);
        spc.expect(der::tag::kSequence, "SpcAttributeTypeAndOptionalValue");
        der::Reader digest_info(spc.expect(der::tag::kSequence, "DigestInfo").content);
        der::Reader alg(digest_info.expect(der::tag::kSequence, "algoritmo do resumo").content);
        sig.digest_algorithm = algorithm_name(der::oid_text(alg.expect(der::tag::kOid, "algoritmo do resumo").content));
        sig.signed_digest = to_hex(digest_info.expect(der::tag::kOctetString, "resumo assinado").content.span());

        std::vector<ParsedCertificate> certs;
        if (auto set = sd.next_if(der::tag::context(0))) {
            der::Reader list(set->content);
            while (!list.at_end()) {
                const der::Element c = list.next();
                if (c.tag != der::tag::kSequence) continue;   // attribute/other certificate formats
                if (certs.size() >= limits.max_certificates) {
                    report.anomalies.push_back("certificados acima do limite de análise; os excedentes foram ignorados");
                    break;
                }
                certs.push_back(parse_certificate(c));
            }
        }
        sd.next_if(der::tag::context(1));   // CRLs
        der::Reader signers(sd.expect(der::tag::kSet, "SignerInfos").content);
        if (signers.at_end()) der::Reader::fail("assinatura sem SignerInfo");
        der::Reader si(signers.expect(der::tag::kSequence, "SignerInfo").content);
        si.expect(der::tag::kInteger, "versão do SignerInfo");
        if (auto ias = si.next_if(der::tag::kSequence)) {
            der::Reader r(ias->content);
            const ByteView issuer = r.expect(der::tag::kSequence, "emissor do assinante").encoded;
            const ByteView serial = r.expect(der::tag::kInteger, "série do assinante").content;
            for (const auto& c : certs) {
                if (same_bytes(c.issuer_der, issuer) && same_bytes(c.serial_content, serial)) sig.signer = c.info;
            }
        } else {
            si.next();   // [0] SubjectKeyIdentifier: not matched to a certificate
        }
        si.expect(der::tag::kSequence, "algoritmo do assinante");
        si.next_if(der::tag::context(0));   // authenticated attributes
        si.expect(der::tag::kSequence, "algoritmo de assinatura");
        si.expect(der::tag::kOctetString, "assinatura");
        std::vector<ByteView> nested_infos;
        if (auto unauth = si.next_if(der::tag::context(1))) {
            der::Reader attrs(unauth->content);
            while (!attrs.at_end()) {
                der::Reader attr(attrs.expect(der::tag::kSequence, "atributo não autenticado").content);
                const std::string oid = der::oid_text(attr.expect(der::tag::kOid, "atributo não autenticado").content);
                const der::Element values = attr.expect(der::tag::kSet, "valores do atributo");
                if (oid == kOidCounterSignature || oid == kOidRfc3161Timestamp) sig.timestamped = true;
                if (oid == kOidNestedSignature) {
                    der::Reader v(values.content);
                    while (!v.at_end()) nested_infos.push_back(v.next().encoded);
                }
            }
        }
        for (auto& c : certs) sig.certificates.push_back(std::move(c.info));
        sig.image_digest = digest(sig.digest_algorithm);
        sig.digest_matches = sig.image_digest && *sig.image_digest == sig.signed_digest;
        (depth == 0 ? report.signatures : nested).push_back(std::move(sig));

        for (const ByteView n : nested_infos) {
            if (static_cast<std::size_t>(depth) + 1 > limits.max_nesting) {
                report.anomalies.push_back("assinaturas aninhadas além do limite de análise");
                break;
            }
            try {
                parse_content_info(n, depth + 1);
            } catch (const Error& e) {
                if (e.code() == ErrorCode::Cancelled) throw;
                report.anomalies.push_back(std::string("assinatura aninhada malformada: ") + e.what());
            }
        }
    }
};

}  // namespace

bool Report::tampered() const {
    return std::any_of(signatures.begin(), signatures.end(),
                       [](const Signature& s) { return s.image_digest && !s.digest_matches; });
}

std::optional<std::string> image_digest(ByteView file, const std::string& algorithm, CancelToken* cancel) {
    const auto layout = layout_of(file);
    if (!layout) return std::nullopt;
    return digest_with_layout(file, *layout, algorithm, cancel);
}

Report inspect(ByteView file, const Limits& limits, CancelToken* cancel) {
    Report report;
    const auto layout = layout_of(file);
    if (!layout || layout->declared_size == 0) return report;
    report.present = true;
    report.table_offset = layout->declared_offset;
    report.table_size = layout->declared_size;
    if (!layout->cert_table) {
        report.error = "a tabela de certificados aponta para fora do arquivo ou para dentro do cabeçalho";
        return report;
    }
    const std::size_t table_end = layout->cert_table->start + layout->cert_table->size;
    report.bytes_after_table = file.size() - table_end;
    if (report.bytes_after_table > 0) {
        report.anomalies.push_back("há " + std::to_string(report.bytes_after_table) +
                                   " bytes depois da tabela de certificados (normalmente ela fica no fim do arquivo)");
    }

    Walker walker{file, *layout, limits, cancel, report, {}, {}};
    std::size_t pos = layout->cert_table->start;
    bool found = false;
    try {
        while (pos < table_end) {
            const auto length = file.le<std::uint32_t>(pos);
            const auto revision = file.le<std::uint16_t>(pos + 4);
            const auto type = file.le<std::uint16_t>(pos + 6);
            if (!length || !revision || !type) throw Error(ErrorCode::InvalidFormat, "cabeçalho WIN_CERTIFICATE truncado");
            if (*length <= 8 || pos + *length > table_end) {
                throw Error(ErrorCode::InvalidFormat, "comprimento inválido em WIN_CERTIFICATE");
            }
            if (*revision != kWinCertRevision2) {
                throw Error(ErrorCode::InvalidFormat, "revisão de WIN_CERTIFICATE desconhecida");
            }
            const std::size_t next = std::min(table_end, pos + *length + ((8 - *length % 8) % 8));
            if (*type == kWinCertTypePkcsSignedData) {
                const ByteView blob = file.clamp(pos + 8, *length - 8);
                der::Reader r(blob);
                const der::Element ci = r.next();
                walker.parse_content_info(ci.encoded, 0);
                found = true;
                for (std::size_t i = pos + 8 + ci.encoded.size(); i < next; ++i) {
                    if (*file.u8(i) != 0) ++report.hidden_bytes;
                }
            } else {
                report.anomalies.push_back("entrada de certificado de tipo não Authenticode (" + std::to_string(*type) + ")");
            }
            pos = next;
        }
        if (!found) report.error = "a tabela de certificados não contém uma assinatura PKCS#7";
    } catch (const Error& e) {
        if (e.code() == ErrorCode::Cancelled) throw;
        report.error = e.what();
    }
    if (report.hidden_bytes > 0) {
        report.anomalies.push_back(std::to_string(report.hidden_bytes) +
                                   " bytes não nulos escondidos depois dos dados da assinatura (fora da área assinada)");
    }
    for (auto& n : walker.nested) report.signatures.push_back(std::move(n));
    return report;
}

std::string_view value_of(TrustState s) {
    switch (s) {
        case TrustState::NotChecked: return "not_checked";
        case TrustState::Trusted: return "trusted";
        case TrustState::Unsigned: return "unsigned";
        case TrustState::BadDigest: return "bad_digest";
        case TrustState::UntrustedRoot: return "untrusted_root";
        case TrustState::Expired: return "expired";
        case TrustState::Revoked: return "revoked";
        case TrustState::Distrusted: return "distrusted";
        case TrustState::ChainIncomplete: return "chain_incomplete";
        case TrustState::Invalid: return "invalid";
    }
    return "not_checked";
}

}  // namespace gk::authenticode
