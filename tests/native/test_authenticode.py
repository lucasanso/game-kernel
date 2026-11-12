"""Authenticode: structure, image hash and tamper detection (portable) and trust verdicts (Windows).

Signed samples are produced at test time with a throwaway self-signed certificate (cryptography) and
osslsigncode; nothing is executed and no key leaves the temporary folder. The oracle is independent of the
C++ DER reader: it walks the PKCS#7 with asn1crypto's TLV parser and hashes the ranges defined by the
Authenticode specification with hashlib.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import random
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from gamekernel.core.models import FileResult

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = str(ROOT / "signatures" / "data" / "game_components.json")
CATALOG = str(ROOT / "contracts" / "threat_catalog.json")
FUZZ_ITERATIONS = int(os.environ.get("GK_FUZZ_ITERATIONS", "300"))
IS_WINDOWS = os.name == "nt"


# ------------------------------------------------------------------------------------------ samples

def _pe(pe32: bool = False, payload: bytes = b"\xC3", sections: int = 2) -> bytes:
    """Small but well-formed PE (headers + `sections` raw sections of 0x200 bytes)."""
    opt_size = 0xE0 if pe32 else 0xF0
    head = bytearray(0x400)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x80)
    head[0x80:0x84] = b"PE\0\0"
    machine = 0x14C if pe32 else 0x8664
    struct.pack_into("<HHIIIHH", head, 0x84, machine, sections, 0, 0, 0, opt_size, 0x0102 if pe32 else 0x0022)
    oh = 0x98
    struct.pack_into("<HBB", head, oh, 0x10B if pe32 else 0x20B, 14, 0)
    struct.pack_into("<III", head, oh + 4, 0x200 * sections, 0, 0)
    struct.pack_into("<II", head, oh + 16, 0x1000, 0x1000)
    if pe32:
        struct.pack_into("<II", head, oh + 24, 0x2000, 0x400000)          # BaseOfData, ImageBase
    else:
        struct.pack_into("<Q", head, oh + 24, 0x140000000)
    struct.pack_into("<II", head, oh + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", head, oh + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<II", head, oh + 56, 0x1000 * (sections + 1), 0x400)
    struct.pack_into("<H", head, oh + 68, 3)
    if pe32:
        struct.pack_into("<IIIII", head, oh + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0)
        struct.pack_into("<I", head, oh + 92, 16)
    else:
        struct.pack_into("<QQQQI", head, oh + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0)
        struct.pack_into("<I", head, oh + 108, 16)
    body = bytearray()
    for i in range(sections):
        sh = oh + opt_size + 40 * i
        head[sh:sh + 8] = (b".text\0\0\0" if i == 0 else b".data\0\0\0")
        struct.pack_into("<IIII", head, sh + 8, 0x200, 0x1000 * (i + 1), 0x200, 0x400 + 0x200 * i)
        struct.pack_into("<I", head, sh + 36, 0x60000020 if i == 0 else 0xC0000040)
        raw = bytearray(0x200)
        chunk = payload if i == 0 else bytes(range(256))
        raw[:len(chunk)] = chunk[:0x200]
        body += raw
    return bytes(head + body)


@pytest.fixture(scope="module")
def signer(tmp_path_factory):
    """Throwaway self-signed code-signing certificate (never written outside the temporary folder)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    if shutil.which("osslsigncode") is None:
        if os.environ.get("GK_REQUIRE_SIGNING") == "1":
            pytest.fail("osslsigncode não instalado")
        pytest.skip("osslsigncode não instalado (necessário para gerar amostras assinadas)")
    folder = tmp_path_factory.mktemp("signer")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Game Kernel Test Signer"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GK Tests")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
            .sign(key, hashes.SHA256()))
    (folder / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    (folder / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return folder


def _sign(signer: Path, data: bytes, tmp: Path, algorithm: str = "sha256", nest: bool = False) -> bytes:
    src, dst = tmp / f"in-{random.getrandbits(32)}.exe", tmp / f"out-{random.getrandbits(32)}.exe"
    src.write_bytes(data)
    cmd = ["osslsigncode", "sign", "-certs", str(signer / "cert.pem"), "-key", str(signer / "key.pem"),
           "-h", algorithm, "-n", "GK test"] + (["-nest"] if nest else []) + ["-in", str(src), "-out", str(dst)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)   # no -t/-ts: never contacts a TSA
    assert result.returncode == 0, result.stdout + result.stderr
    return dst.read_bytes()


# ------------------------------------------------------------------------------------------ oracle

def _children(data: bytes):
    from asn1crypto import parser
    out, pos = [], 0
    while pos < len(data):
        cls, _method, tag, header, contents, trailer = parser.parse(data[pos:], strict=False)
        n = len(header) + len(contents) + len(trailer)
        out.append((cls, tag, contents, data[pos:pos + n]))
        pos += n
    return out


def _first(data: bytes):
    """First TLV only (WIN_CERTIFICATE blobs are zero-padded after the DER)."""
    from asn1crypto import parser
    cls, _method, tag, header, contents, trailer = parser.parse(data, strict=False)
    return cls, tag, contents, data[:len(header) + len(contents) + len(trailer)]


def _oid(contents: bytes) -> str:
    from asn1crypto import core
    return core.ObjectIdentifier.load(b"\x06" + bytes([len(contents)]) + contents).dotted


_ALG = {"1.2.840.113549.2.5": "md5", "1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.1": "sha256",
        "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}


def _oracle_locations(data: bytes):
    """Excluded ranges per the Authenticode PE specification (checksum, cert dir entry, cert table)."""
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    opt_size = struct.unpack_from("<H", data, lfanew + 20)[0]
    oh = lfanew + 24
    magic = struct.unpack_from("<H", data, oh)[0]
    cert_at = oh + (144 if magic == 0x20B else 128)
    omit = [(oh + 64, 4), (cert_at, 8)]
    address, size = struct.unpack_from("<II", data, cert_at)
    if size and address >= oh + opt_size and address + size <= len(data):
        omit.append((address, size))
    return sorted(omit), (address, size)


def _oracle_digest(data: bytes, algorithm: str) -> str:
    omit, _ = _oracle_locations(data)
    h = hashlib.new(algorithm)
    at = 0
    for start, size in omit:
        h.update(data[at:start])
        at = max(at, start + size)
    h.update(data[at:])
    return h.hexdigest()


def _oracle_signatures(blob: bytes, depth: int = 0, out=None):
    from asn1crypto import core, x509
    out = [] if out is None else out
    ci = _children(_first(blob)[2])
    assert _oid(ci[0][2]) == "1.2.840.113549.1.7.2"
    sd = _children(_children(ci[1][2])[0][2])
    encap = _children(sd[2][2])
    spc = _children(_children(encap[1][2])[0][2])
    digest_info = _children(spc[1][2])
    algorithm = _ALG[_oid(_children(digest_info[0][2])[0][2])]
    rest, certs = sd[3:], []
    if rest and rest[0][0] == 2 and rest[0][1] == 0:
        certs = [x509.Certificate.load(c[3]) for c in _children(rest[0][2]) if c[1] == 16]
        rest = rest[1:]
    if rest and rest[0][0] == 2 and rest[0][1] == 1:
        rest = rest[1:]
    si = _children(_children(rest[0][2])[0][2])
    ias = _children(si[1][2])
    issuer, serial = ias[0][3], core.Integer.load(ias[1][3]).native
    leaf = next((c for c in certs if c.issuer.dump() == issuer and c.serial_number == serial), None)
    out.append({"depth": depth, "digest_algorithm": algorithm, "signed_digest": digest_info[1][2].hex(),
                "signer_cn": leaf.subject.native.get("common_name") if leaf else None,
                "signer_sha256": hashlib.sha256(leaf.dump()).hexdigest() if leaf else None,
                "serial": ias[1][2].hex(), "certificates": len(certs)})
    nested = []
    if si[-1][0] == 2 and si[-1][1] == 1:
        for attr in _children(si[-1][2]):
            a = _children(attr[2])
            if _oid(a[0][2]) == "1.3.6.1.4.1.311.2.4.1":
                nested += [v[3] for v in _children(a[1][2])]
    return out, nested


def _oracle(data: bytes):
    _, (address, size) = _oracle_locations(data)
    sigs, pending = [], []
    pos, end = address, address + size
    while pos < end:
        length = struct.unpack_from("<I", data, pos)[0]
        found, nested = _oracle_signatures(data[pos + 8:pos + length])
        sigs += found
        pending += nested
        pos += length + (8 - length % 8) % 8
    for blob in pending:
        found, _ = _oracle_signatures(blob, 1)
        sigs += found
    for s in sigs:
        s["image_digest"] = _oracle_digest(data, s["digest_algorithm"])
    return sigs


def _assert_matches_oracle(native, data: bytes):
    report = native.authenticode_inspect(data)
    expected = _oracle(data)
    assert report["present"] and report["error"] is None, report
    assert len(report["signatures"]) == len(expected)
    for got, exp in zip(report["signatures"], expected):
        assert got["depth"] == exp["depth"]
        assert got["digest_algorithm"] == exp["digest_algorithm"]
        assert got["signed_digest"] == exp["signed_digest"]
        assert got["image_digest"] == exp["image_digest"]
        assert got["digest_matches"] == (exp["signed_digest"] == exp["image_digest"])
        assert len(got["certificates"]) == exp["certificates"]
        assert (got["signer"] or {}).get("subject_cn") == exp["signer_cn"]
        assert (got["signer"] or {}).get("sha256") == exp["signer_sha256"]
        if got["signer"]:
            assert got["signer"]["serial"] == exp["serial"]
    return report


# ------------------------------------------------------------------------------------------ hashes

@pytest.mark.parametrize("length", [0, 1, 55, 56, 57, 63, 64, 65, 111, 112, 119, 120, 127, 128, 129, 1000, 100_003])
def test_sha1_sha384_sha512_match_hashlib(native, length):
    data = random.Random(length).randbytes(length)
    assert native.sha1_bytes(data) == hashlib.sha1(data).hexdigest()
    assert native.sha512_bytes(data) == hashlib.sha512(data).hexdigest()
    assert native.sha512_bytes(data, True) == hashlib.sha384(data).hexdigest()


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("algorithm", ["md5", "sha1", "sha256", "sha384", "sha512"])
def test_image_digest_matches_specification(native, pe32, algorithm):
    data = _pe(pe32=pe32, payload=b"\x90" * 100 + b"\xC3") + b"overlay data"
    assert native.authenticode_image_digest(data, algorithm) == _oracle_digest(data, algorithm)
    assert native.authenticode_image_digest(b"not a pe", algorithm) is None
    assert native.authenticode_image_digest(data, "whirlpool") is None


# ------------------------------------------------------------------------------------------ structure

def test_unsigned_pe(native):
    report = native.authenticode_inspect(_pe())
    assert not report["present"] and report["signatures"] == [] and not report["tampered"]


@pytest.mark.parametrize("pe32", [False, True])
@pytest.mark.parametrize("algorithm", ["sha256", "sha1", "sha512"])
def test_signed_samples_match_oracle(native, signer, tmp_path, pe32, algorithm):
    signed = _sign(signer, _pe(pe32=pe32), tmp_path, algorithm)
    report = _assert_matches_oracle(native, signed)
    sig = report["signatures"][0]
    assert sig["digest_matches"] and not report["tampered"]
    assert sig["signer"]["subject_cn"] == "Game Kernel Test Signer" and sig["signer"]["subject_o"] == "GK Tests"
    assert sig["signer"]["self_issued"] and sig["signer"]["not_after"].endswith("Z")
    assert report["anomalies"] == [] and report["hidden_bytes"] == 0 and report["bytes_after_table"] == 0


def test_dual_signature_with_nested_sha1(native, signer, tmp_path):
    dual = _sign(signer, _sign(signer, _pe(), tmp_path, "sha256"), tmp_path, "sha1", nest=True)
    report = _assert_matches_oracle(native, dual)
    assert [(s["depth"], s["digest_algorithm"]) for s in report["signatures"]] == [(0, "sha256"), (1, "sha1")]
    assert all(s["digest_matches"] for s in report["signatures"])


def test_modification_after_signing_is_detected(native, signer, tmp_path):
    signed = bytearray(_sign(signer, _pe(), tmp_path))
    signed[0x400 + 10] ^= 0xFF                                   # code byte
    report = _assert_matches_oracle(native, bytes(signed))
    assert report["tampered"] and not report["signatures"][0]["digest_matches"]


def test_excluded_fields_do_not_break_the_signature(native, signer, tmp_path):
    signed = bytearray(_sign(signer, _pe(), tmp_path))
    struct.pack_into("<I", signed, 0x98 + 64, 0xDEADBEEF)          # PE checksum is excluded by the specification
    assert not native.authenticode_inspect(bytes(signed))["tampered"]


def test_data_hidden_after_the_signature(native, signer, tmp_path):
    """CVE-2013-3900 pattern: bytes appended inside WIN_CERTIFICATE, outside the signed area."""
    signed = bytearray(_sign(signer, _pe(), tmp_path))
    cert_at = 0x98 + 144
    address, size = struct.unpack_from("<II", signed, cert_at)
    hidden = b"PAYLOAD!" * 4
    length = struct.unpack_from("<I", signed, address)[0]
    blob = signed[address:address + length] + hidden
    struct.pack_into("<I", blob, 0, len(blob))
    signed = signed[:address] + blob
    struct.pack_into("<II", signed, cert_at, address, len(blob))
    report = native.authenticode_inspect(bytes(signed))
    assert not report["tampered"] and report["hidden_bytes"] == len(hidden)
    assert any("escondidos" in a for a in report["anomalies"])


@pytest.mark.parametrize("mutation", ["outside_file", "bad_revision", "short_length", "garbage_der", "not_signed_data"])
def test_malformed_tables_are_reported_not_fatal(native, signer, tmp_path, mutation):
    signed = bytearray(_sign(signer, _pe(), tmp_path))
    cert_at = 0x98 + 144
    address, size = struct.unpack_from("<II", signed, cert_at)
    if mutation == "outside_file":
        struct.pack_into("<I", signed, cert_at, len(signed) + 0x1000)
    elif mutation == "bad_revision":
        struct.pack_into("<H", signed, address + 4, 0x0100)
    elif mutation == "short_length":
        struct.pack_into("<I", signed, address, 4)
    elif mutation == "garbage_der":
        signed[address + 8:address + 40] = b"\x30\x84\xff\xff\xff\xff" + b"\0" * 26
    else:
        signed[address + 8 + 6:address + 8 + 15] = b"\x06\x07\x2a\x86\x48\x86\xf7\x0d\x01"   # other OID
    report = native.authenticode_inspect(bytes(signed))
    assert report["present"] and report["error"] and report["signatures"] == []


def test_fuzzed_certificate_tables_never_crash(native, signer, tmp_path):
    base = _sign(signer, _sign(signer, _pe(), tmp_path, "sha256"), tmp_path, "sha1", nest=True)
    address, size = struct.unpack_from("<II", base, 0x98 + 144)
    rng = random.Random(1234)
    for _ in range(FUZZ_ITERATIONS):
        data = bytearray(base)
        for _ in range(rng.randint(1, 12)):
            pos = address + rng.randrange(size)
            data[pos] = rng.randrange(256) if rng.random() < 0.8 else rng.choice([0x00, 0x80, 0x84, 0xFF])
        if rng.random() < 0.1:
            data = data[:address + rng.randrange(size)]
        report = native.authenticode_inspect(bytes(data))
        assert isinstance(report["signatures"], list)


# ------------------------------------------------------------------------------------------ evidence

@pytest.fixture(scope="module")
def rules(native):
    return native.AnalysisRules.load([str(ROOT / "signatures" / "yara")],
                                     str(ROOT / "signatures" / "internal" / "indicators.yar"))


def _analyze(native, rules, data: bytes, name: str) -> dict:
    doc = native.analyze_bytes(data, name, path="/g/Game/" + name, rules=rules)["result"]
    assert FileResult.from_dict(doc).to_dict() == doc
    return doc


def test_evidence_for_intact_and_tampered_signatures(native, rules, signer, tmp_path):
    signed = _sign(signer, _pe(), tmp_path)
    intact = _analyze(native, rules, signed, "Game.exe")
    ev = {e["rule_id"]: e for e in intact["evidences"]}
    assert ev["PE.Signature.Present"]["severity"] == "INFO"
    assert intact["features"]["signed"] and intact["features"]["signature_valid"] is None   # claimed, not verified
    assert "authenticode" in intact["engines"]

    tampered = bytearray(signed)
    tampered[0x400 + 3] ^= 0x01
    doc = _analyze(native, rules, bytes(tampered), "Game.exe")
    ev = {e["rule_id"]: e for e in doc["evidences"]}
    assert "PE.Signature.Present" not in ev
    t = ev["PE.Signature.Tampered"]
    assert t["severity"] == "LOW" and t["confidence"] == "HIGH" and t["category"] == "structural_anomaly"
    assert t["details"]["assinante_declarado"] == "Game Kernel Test Signer"
    assert t["details"]["resumo_assinado"] != t["details"]["resumo_calculado"]
    assert t["locations"][0]["kind"] == "certificate"
    assert doc["features"]["signed"] and doc["features"]["signature_valid"] is False

    # Risk: modified (not suspicious) with no other evidence; mitigated inside a recognised crack component.
    assessed = {d["name"]: d for d in native.risk_assess([doc], COMPONENTS, CATALOG)}["Game.exe"]
    assert assessed["classification"] == "modified" and assessed["risk"] == "LOW"
    assert assessed["crack_status"] == "modified_no_threat"
    assert any("alterado depois de assinado" in line for line in assessed["explanation"])
    steamless = _analyze(native, rules, bytes(tampered), "Game.unpacked.exe")
    out = {d["name"]: d for d in native.risk_assess([steamless], COMPONENTS, CATALOG)}["Game.unpacked.exe"]
    tamper = next(e for e in out["evidences"] if e["rule_id"] == "PE.Signature.Tampered")
    assert tamper["adjusted_severity"] == "INFO" and out["classification"] == "modified"


def test_hidden_data_and_malformed_evidence(native, rules, signer, tmp_path):
    signed = bytearray(_sign(signer, _pe(), tmp_path))
    struct.pack_into("<H", signed, struct.unpack_from("<I", signed, 0x98 + 144)[0] + 4, 0x0100)
    doc = _analyze(native, rules, bytes(signed), "Game.exe")
    ev = {e["rule_id"]: e for e in doc["evidences"]}
    assert ev["PE.Signature.Malformed"]["severity"] == "LOW"
    assert doc["features"]["signature_valid"] is False


def test_archive_members_get_structural_checks(native, rules, signer, tmp_path):
    import io
    import zipfile
    signed = bytearray(_sign(signer, _pe(), tmp_path))
    signed[0x400 + 3] ^= 0x01
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("bin/Game.exe", bytes(signed))
    out = native.analyze_bytes(buf.getvalue(), "pack.zip", path="/g/pack.zip", rules=rules)
    member = next(m for m in out["members"] if m["name"] == "Game.exe")
    assert "PE.Signature.Tampered" in {e["rule_id"] for e in member["evidences"]}


# ------------------------------------------------------------------------------------------ trust

@pytest.mark.skipif(IS_WINDOWS, reason="comportamento fora do Windows")
def test_trust_is_reported_as_not_checked_outside_windows(native, tmp_path):
    assert native.authenticode_trust_supported() is False
    f = tmp_path / "a.exe"
    f.write_bytes(_pe())
    t = native.authenticode_verify_trust(str(f))
    assert t["state"] == "not_checked" and "Windows" in t["message"]


@pytest.mark.skipif(not IS_WINDOWS, reason="WinVerifyTrust só existe no Windows")
class TestWindowsTrust:
    SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"

    def test_catalog_signed_system_dll(self, native):
        t = native.authenticode_verify_trust(str(self.SYSTEM32 / "kernel32.dll"))
        assert t["state"] == "trusted", t
        assert t["from_catalog"] and t["catalog"].lower().endswith(".cat")
        assert "Microsoft" in t["signer"] and len(t["signer_thumbprint"]) == 64

    def test_embedded_signature_of_python(self, native):
        exe = Path(sys.base_exec_prefix) / "python.exe"
        report = _assert_matches_oracle(native, exe.read_bytes())   # real-world signature vs oracle
        assert report["signatures"][0]["digest_matches"] and report["signatures"][0]["timestamped"]
        t = native.authenticode_verify_trust(str(exe))
        # Offline: the chain must be buildable from the certificates on this machine.
        assert t["state"] in ("trusted", "chain_incomplete"), t
        if t["state"] == "trusted":
            assert "Python Software Foundation" in t["signer"] and not t["from_catalog"]

    def test_modified_copy_has_bad_digest(self, native, tmp_path):
        exe = Path(sys.base_exec_prefix) / "python.exe"
        data = bytearray(exe.read_bytes())
        data[0x1000] ^= 0x01
        copy = tmp_path / "python_mod.exe"
        copy.write_bytes(bytes(data))
        assert native.authenticode_inspect(bytes(data))["tampered"]
        assert native.authenticode_verify_trust(str(copy))["state"] == "bad_digest"

    def test_unsigned_file(self, native, tmp_path):
        f = tmp_path / "unsigned.exe"
        f.write_bytes(_pe())
        t = native.authenticode_verify_trust(str(f))
        assert t["state"] == "unsigned" and not t["from_catalog"]

    def test_analysis_reports_trusted_signer(self, native, rules):
        out = native.analyze_file(str(self.SYSTEM32 / "kernel32.dll"), rules)
        doc = out["result"]
        assert "wintrust" in doc["engines"]
        assert doc["features"]["signature_valid"] is True and "Microsoft" in doc["features"]["signer"]
        ev = next(e for e in doc["evidences"] if e["rule_id"] == "PE.Signature.Trusted")
        assert ev["severity"] == "INFO" and ev["details"]["catalogo"].lower().endswith(".cat")


def test_report_signature_labels():
    from gamekernel.reports.render_html import _signature
    assert _signature({"signed": True, "signature_valid": True, "signer": "Valve"}) == "válida — Valve"
    assert _signature({"signed": True, "signature_valid": False}) == "presente, inválida"
    assert _signature({"signed": True, "signature_valid": None}) == "presente, não verificada"
    assert _signature({"signed": False, "signature_valid": None}) == "ausente"
