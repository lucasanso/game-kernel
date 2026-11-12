"""Python reference verifier × C++ verifier (gk-update): same decision and same error code for
valid packages, every kind of tampering, signed-but-invalid manifests and random mutations."""

from __future__ import annotations

import hashlib
import json
import random
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gamekernel.updates import package as pkg

from .conftest import base_manifest, run_gk_update, write_raw_package


def python_verdict(path, keys, app_version="1.0.0") -> tuple[bool, str | None, str | None]:
    try:
        info = pkg.verify_package(path, keys, app_version)
        return True, None, info.key_id
    except pkg.PackageError as exc:
        return False, exc.code, None


def cpp_verdict(tool, path, keys_dir, app_version="1.0.0") -> tuple[bool, str | None, str | None]:
    code, out = run_gk_update(tool, "verify", path, "--keys", keys_dir, "--app-version", app_version)
    assert code == (0 if out["ok"] else 1)
    return out["ok"], (out.get("error") or {}).get("code"), out.get("key_id")


def assert_same(tool, path, keys, keys_dir, app_version="1.0.0", expected_code=None):
    py = python_verdict(path, keys, app_version)
    cpp = cpp_verdict(tool, path, keys_dir, app_version)
    assert py == cpp, f"divergência Python={py} C++={cpp}"
    if expected_code is not None:
        assert py[1] == expected_code
    return py


@pytest.fixture
def valid_package(tmp_path, keypair, components):
    private, keys_dir, keys = keypair
    path = tmp_path / "ok.gkpkg"
    manifest = pkg.build_package(path, private, "2026.11.12.1", components, publisher="tests")
    return path, manifest


def test_valid_package_accepted_by_both(gk_update, keypair, valid_package):
    private, keys_dir, keys = keypair
    path, manifest = valid_package
    ok, code, kid = assert_same(gk_update, path, keys, keys_dir)
    assert ok and kid == manifest["signing_key_id"]
    _, out = run_gk_update(gk_update, "verify", path, "--keys", keys_dir)
    assert out["manifest"] == json.loads(json.dumps(manifest))


def _mutate(data: bytes, offset: int, xor: int = 0x01) -> bytes:
    return data[:offset] + bytes([data[offset] ^ xor]) + data[offset + 1:]


def test_tampering_cases(gk_update, keypair, valid_package, tmp_path):
    private, keys_dir, keys = keypair
    path, manifest = valid_package
    data = path.read_bytes()
    manifest_len = struct.unpack_from("<I", data, 8)[0]
    payload_start = 12 + manifest_len + 4 + 64
    cases = {
        "payload_byte": (_mutate(data, payload_start + 3), "hash_mismatch"),
        "last_byte": (_mutate(data, len(data) - 1), "hash_mismatch"),
        "manifest_byte": (_mutate(data, 40), "bad_signature"),
        "signature_byte": (_mutate(data, 12 + manifest_len + 4 + 10), "bad_signature"),
        "magic": (b"PK\x03\x04" + data[4:], "not_a_package"),
        "format_version": (data[:6] + b"\x02" + data[7:], "unsupported_format"),
        "truncated_payload": (data[:-5], "truncated"),
        "truncated_header": (data[:10], "truncated"),
        "truncated_signature": (data[:12 + manifest_len + 20], "truncated"),
        "trailing": (data + b"x", "trailing_data"),
        "huge_manifest_len": (data[:8] + struct.pack("<I", pkg.MAX_MANIFEST + 1) + data[12:], "invalid_header"),
        "zero_manifest_len": (data[:8] + struct.pack("<I", 0) + data[12:], "invalid_header"),
        "bad_sig_len": (data[:12 + manifest_len] + struct.pack("<I", 63) + data[12 + manifest_len + 4:], "invalid_header"),
        "empty": (b"", "truncated"),
    }
    for name, (blob, expected) in cases.items():
        target = tmp_path / f"{name}.gkpkg"
        target.write_bytes(blob)
        assert_same(gk_update, target, keys, keys_dir, expected_code=expected)


def test_untrusted_key_and_missing_keys(gk_update, keypair, valid_package, tmp_path):
    private, keys_dir, keys = keypair
    path, _ = valid_package
    other = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization

    other_dir = tmp_path / "other-keys"
    other_dir.mkdir()
    (other_dir / "x.pub").write_bytes(other.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    from gamekernel.crypto_utils import key_id

    assert_same(gk_update, path, {key_id(other.public_key()): other.public_key()}, other_dir,
                expected_code="bad_signature")
    empty = tmp_path / "no-keys"
    empty.mkdir()
    assert_same(gk_update, path, {}, empty, expected_code="no_trusted_keys")
    (empty / "broken.pub").write_text("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
    _, out = run_gk_update(gk_update, "verify", path, "--keys", empty)
    assert out["error"]["code"] == "no_trusted_keys" and out["key_problems"]


def test_min_app_version(gk_update, keypair, tmp_path, components):
    private, keys_dir, keys = keypair
    path = tmp_path / "future.gkpkg"
    pkg.build_package(path, private, "2026.11.12.1", components, publisher="tests", min_app_version="9.0.0")
    assert_same(gk_update, path, keys, keys_dir, app_version="1.0.0", expected_code="incompatible_app")
    assert_same(gk_update, path, keys, keys_dir, app_version="9.0.0")


SIGNED_BUT_INVALID = {
    "path_traversal": lambda m: m["files"][0].update(path="yara/../evil.yar"),
    "absolute_path": lambda m: m["files"][0].update(path="/etc/passwd"),
    "backslash": lambda m: m["files"][0].update(path="yara\\x.yar"),
    "bad_extension": lambda m: m["files"][0].update(path="yara/payload.exe"),
    "reserved_name": lambda m: m["files"][0].update(path="yara/CON.yar"),
    "reserved_name_lower": lambda m: m["files"][0].update(path="ioc/nul.json"),
    "trailing_newline_path": lambda m: m["files"][0].update(path="yara/x.yar\n"),
    "unknown_component": lambda m: m["components"].update(drivers={"version": "1"}),
    "undeclared_component": lambda m: m["components"].pop("yara"),
    "negative_size": lambda m: m["files"][0].update(size=-1),
    "fractional_size": lambda m: m["files"][0].update(size=1.5),
    "bool_size": lambda m: m["files"][0].update(size=True),
    "huge_size": lambda m: m["files"][0].update(size=pkg.MAX_FILE_SIZE + 1),
    "uppercase_sha": lambda m: m["files"][0].update(sha256=m["files"][0]["sha256"].upper()),
    "short_sha": lambda m: m["files"][0].update(sha256="ab" * 16),
    "bad_version": lambda m: m.update(package_version="v2"),
    "bad_app_version": lambda m: m.update(min_app_version="1.0"),
    "bad_key_id": lambda m: m.update(signing_key_id="XYZ"),
    "wrong_format": lambda m: m.update(format="zip"),
    "format_version_2": lambda m: m.update(format_version=2),
    "format_version_bool": lambda m: m.update(format_version=True),
    "missing_field": lambda m: m.pop("publisher"),
    "empty_publisher": lambda m: m.update(publisher=""),
    "no_files": lambda m: m.update(files=[]),
    "duplicate_file": lambda m: m["files"].append(dict(m["files"][0])),
    "duplicate_case": lambda m: m["files"].append(dict(m["files"][0], path=m["files"][0]["path"].upper()
                                                       .replace("YARA/", "yara/").replace(".YAR", ".yar"))),
    "component_without_version": lambda m: m["components"].update(yara={}),
}


@pytest.mark.parametrize("case", sorted(SIGNED_BUT_INVALID))
def test_signed_but_invalid_manifests(gk_update, keypair, tmp_path, case):
    private, keys_dir, keys = keypair
    payload = b"rule x { condition: true }\n"
    manifest = base_manifest(private, {"yara/x.yar": payload})
    SIGNED_BUT_INVALID[case](manifest)
    path = write_raw_package(tmp_path / f"{case}.gkpkg", private, manifest, [payload])
    ok, code, _ = assert_same(gk_update, path, keys, keys_dir)
    assert not ok and code in ("invalid_manifest", "hash_mismatch", "truncated", "trailing_data"), code


def test_signed_garbage_manifest(gk_update, keypair, tmp_path):
    private, keys_dir, keys = keypair
    for name, body in {"not_json": b"{nope", "array": b"[1,2]", "bad_utf8": b'{"a":"\xff"}', "nan": b'{"a": NaN}'}.items():
        path = write_raw_package(tmp_path / f"{name}.gkpkg", private, body, [])
        assert_same(gk_update, path, keys, keys_dir, expected_code="invalid_manifest")


def test_zero_length_file_is_supported(gk_update, keypair, tmp_path):
    private, keys_dir, keys = keypair
    manifest = base_manifest(private, {"ioc/empty.json": b""})
    path = write_raw_package(tmp_path / "zero.gkpkg", private, manifest, [b""])
    assert_same(gk_update, path, keys, keys_dir)


def test_random_mutations_never_accepted(gk_update, keypair, valid_package, tmp_path):
    """Every byte of a package is covered by the signature or a signed hash: any mutation must be
    rejected, by both implementations, with the same error code."""
    private, keys_dir, keys = keypair
    path, _ = valid_package
    data = path.read_bytes()
    rng = random.Random(20261112)
    for i in range(60):
        kind = rng.choice(("flip", "truncate", "insert"))
        if kind == "flip":
            blob = _mutate(data, rng.randrange(len(data)), rng.randrange(1, 256))
        elif kind == "truncate":
            blob = data[:rng.randrange(len(data))]
        else:
            pos = rng.randrange(len(data))
            blob = data[:pos] + bytes([rng.randrange(256)]) + data[pos:]
        target = tmp_path / f"mut{i}.gkpkg"
        target.write_bytes(blob)
        ok, code, _ = assert_same(gk_update, target, keys, keys_dir)
        assert not ok, f"mutação {kind} aceita"


def test_python_and_cpp_key_ids_match(gk_update, keypair, valid_package):
    private, keys_dir, keys = keypair
    path, manifest = valid_package
    _, out = run_gk_update(gk_update, "verify", path, "--keys", keys_dir)
    assert out["key_id"] == list(keys)[0] == manifest["signing_key_id"]
    assert hashlib.sha256(b"").hexdigest()  # sanity: hashlib available
