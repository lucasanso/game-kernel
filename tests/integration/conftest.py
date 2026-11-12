"""Fixtures for offline update tests: keys, components, raw package writer, native gk-update tool."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import struct
import subprocess
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gamekernel.crypto_utils import key_id
from gamekernel.updates import package as pkg
from .native_build import ROOT, build_project

YARA_RULE = '''rule GK_Test_Marker
{
    meta:
        description = "Marcador de teste do Game Kernel"
        category = "test_file"
        severity = "INFO"
        author = "Game Kernel tests"
        fp_note = "Somente arquivos de teste contêm este marcador."
        reference_date = "2026-11-12"
    strings:
        $a = "GAMEKERNEL-TEST-MARKER-7f3c"
    condition:
        $a and filename != "x"
}
'''


def make_cvd(body: bytes = b"", version: int = 27450, sigs: int = 5, md5: str | None = None) -> bytes:
    if not body:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"44d88612fea8a8f36de82e1278abb02f:68:Gk.Test.Sig\n"
            info = tarfile.TarInfo("test.hdb")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        body = buf.getvalue()
    digest = md5 or hashlib.md5(body).hexdigest()
    header = f"ClamAV-VDB:12 Nov 2026 10-00 +0000:{version}:{sigs}:90:{digest}:dsigdsig:gk-tests:1731405600".encode()
    return header.ljust(512, b" ") + body


@pytest.fixture
def keypair(tmp_path):
    private = Ed25519PrivateKey.generate()
    keys_dir = tmp_path / "trusted-keys"
    keys_dir.mkdir()
    (keys_dir / "release.pub").write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return private, keys_dir, {key_id(private.public_key()): private.public_key()}


@pytest.fixture
def components(tmp_path):
    base = tmp_path / "components"
    yara_dir, ioc_dir, clam_dir = base / "yara", base / "ioc", base / "clamav"
    for d in (yara_dir, ioc_dir, clam_dir):
        d.mkdir(parents=True)
    (yara_dir / "gamekernel_test.yar").write_text(YARA_RULE, encoding="utf-8")
    (ioc_dir / "local.json").write_text(json.dumps({"format": "gamekernel-ioc", "version": "2026.11.12", "entries": [
        {"sha256": "a" * 64, "verdict": "bad", "name": "Teste", "category": "trojan", "severity": "HIGH",
         "source": "testes"},
        {"sha256": "b" * 64, "verdict": "good", "name": "Jogo legítimo"},
    ]}), encoding="utf-8")
    (clam_dir / "gamekernel.hdb").write_text("44d88612fea8a8f36de82e1278abb02f:68:Gk.Test.Eicar\n", encoding="utf-8")
    (clam_dir / "gamekernel.ndb").write_text("Gk.Test.Marker:0:*:47414d454b45524e454c\n", encoding="utf-8")
    (clam_dir / "daily.cvd").write_bytes(make_cvd())
    return {"yara": yara_dir, "ioc": ioc_dir, "clamav": clam_dir}


def write_raw_package(path: Path, private: Ed25519PrivateKey, manifest: dict | bytes, payloads: list[bytes],
                      magic: bytes = pkg.MAGIC) -> Path:
    """Write a container WITHOUT any validation (to craft signed-but-invalid packages)."""
    body = manifest if isinstance(manifest, bytes) else json.dumps(manifest).encode("utf-8")
    prefix = magic + struct.pack("<I", len(body)) + body
    path.write_bytes(prefix + struct.pack("<I", 64) + private.sign(prefix) + b"".join(payloads))
    return path


def base_manifest(private: Ed25519PrivateKey, files: dict[str, bytes], version: str = "2026.11.12.1") -> dict:
    comps = sorted({p.split("/", 1)[0] for p in files})
    return {
        "format": "gamekernel-update", "format_version": 1, "package_id": "test-package", "package_version": version,
        "created_at": "2026-11-12T10:00:00Z", "publisher": "tests", "description": "", "min_app_version": "1.0.0",
        "components": {c: {"version": version} for c in comps},
        "files": [{"path": p, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()} for p, d in files.items()],
        "signing_key_id": key_id(private.public_key()),
    }


@pytest.fixture(scope="session")
def gk_update():
    return build_project("native-updates", ROOT / "native" / "updates", "gk-update")


def run_gk_update(tool: Path, *args: str) -> tuple[int, dict]:
    proc = subprocess.run([str(tool), *map(str, args)], capture_output=True, text=True, timeout=300)
    lines = proc.stdout.strip().splitlines()
    assert lines, f"sem saída do gk-update: {proc.stderr}"
    return proc.returncode, json.loads(lines[-1])
