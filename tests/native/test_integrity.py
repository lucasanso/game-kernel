"""Installation integrity: C++ gk::integrity against gamekernel.core.integrity, the release tool, and the
orchestrator refusing to launch a modified bundled binary.

Keys are generated at test time in temporary folders (never committed)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from gamekernel import crypto_utils
from gamekernel.core import integrity as py_integrity

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "build_integrity_manifest.py"
EXE = ".exe" if os.name == "nt" else ""


def _keypair(folder: Path, name: str) -> tuple[Path, Path]:
    private_pem, public_pem = crypto_utils.generate_keypair(None)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.key").write_bytes(private_pem)
    (folder / f"{name}.pub").write_bytes(public_pem)
    return folder / f"{name}.key", folder / f"{name}.pub"


def _build(root: Path, key: Path | None, version: str = "1.2.3") -> subprocess.CompletedProcess:
    args = [sys.executable, str(TOOL), str(root), "--version", version]
    args += ["--key", str(key), "--no-password"] if key else ["--unsigned"]
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    return result


@pytest.fixture
def install(tmp_path):
    root = tmp_path / "GameKernel"
    (root / "third_party" / "clamav").mkdir(parents=True)
    (root / "signatures" / "keys").mkdir(parents=True)
    (root / "data").mkdir()
    (root / "gk-scanworker.exe").write_bytes(b"MZ worker" + bytes(5000))
    (root / "third_party" / "clamav" / "clamscan.exe").write_bytes(b"MZ clamscan")
    (root / "docs ç").mkdir()
    (root / "docs ç" / "leia-me.txt").write_text("olá", encoding="utf-8")
    (root / "data" / "gamekernel.db").write_bytes(b"user data is not part of the manifest")
    key, pub = _keypair(tmp_path / "private", "release")
    shutil.copy(pub, root / "signatures" / "keys" / "release.pub")
    return root, key


@pytest.fixture(autouse=True)
def _python_uses_the_installation_keys(monkeypatch, request):
    """gamekernel.core.integrity trusts the keys of the running program (app_paths.trusted_keys_dir()); in the
    product that is the installation being checked. Point it at the test installation's keys."""
    if "install" in request.fixturenames:
        root, _ = request.getfixturevalue("install")
        monkeypatch.setattr("gamekernel.app_paths.trusted_keys_dir", lambda: root / "signatures" / "keys")


def _both(native, root: Path):
    py_integrity.clear_caches()
    py = py_integrity.check_installation(root)
    cpp = native.IntegrityVerifier(str(root), [str(root / "signatures" / "keys")]).check_installation()
    return py, cpp


def _same(py, cpp):
    assert cpp["ok"] == py.ok
    assert cpp["manifest_present"] == py.manifest_present
    assert cpp["signature_valid"] == py.signature_valid
    assert cpp["signer_key_id"] == py.signer_key_id
    assert cpp["verified"] == py.verified
    assert sorted(cpp["missing"]) == sorted(py.missing) and sorted(cpp["modified"]) == sorted(py.modified)
    assert cpp["detail"] == py.detail


def test_key_ids_match_python(native, tmp_path):
    _, pub = _keypair(tmp_path, "k")
    expected = crypto_utils.key_id(crypto_utils.load_public_key(pub.read_bytes()))
    assert native.integrity_key_id(pub.read_text()) == expected
    assert native.integrity_key_id("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----") is None


def test_signed_intact_installation(native, install):
    root, key = install
    out = _build(root, key)
    assert "assinado pela chave" in out.stdout
    py, cpp = _both(native, root)
    _same(py, cpp)
    assert cpp["ok"] and cpp["signature_valid"] is True and cpp["verified"] == 4
    assert "data/gamekernel.db" not in py_integrity.load_manifest(root)[0]["files"]


@pytest.mark.parametrize("damage", ["modify", "delete", "edit_manifest", "untrusted_key", "unsigned", "no_manifest",
                                    "bad_format"])
def test_every_state_matches_python(native, install, tmp_path, damage):
    root, key = install
    _build(root, None if damage == "unsigned" else key)
    if damage == "modify":
        (root / "gk-scanworker.exe").write_bytes(b"MZ worker" + bytes(4999) + b"!")
    elif damage == "delete":
        (root / "docs ç" / "leia-me.txt").unlink()
    elif damage == "edit_manifest":
        raw = (root / "integrity_manifest.json").read_bytes().replace(b'"1.2.3"', b'"1.2.4"')
        (root / "integrity_manifest.json").write_bytes(raw)
    elif damage == "untrusted_key":
        _, other = _keypair(tmp_path / "other", "attacker")
        shutil.copy(other, root / "signatures" / "keys" / "release.pub")
    elif damage == "no_manifest":
        (root / "integrity_manifest.json").unlink()
        (root / "integrity_manifest.sig").unlink()
    elif damage == "bad_format":
        (root / "integrity_manifest.json").write_text('{"format": "outro"}')
    py, cpp = _both(native, root)
    _same(py, cpp)
    expected_ok = damage == "unsigned"
    assert cpp["ok"] is expected_ok


def _py_component(path: Path, root: Path):
    py_integrity.clear_caches()
    return py_integrity.verify_component(path, root)[0]


@pytest.mark.parametrize("state", ["verified", "modified", "not_listed", "outside", "no_manifest", "bad_manifest"])
def test_component_checks_match_python(native, install, tmp_path, state):
    root, key = install
    _build(root, key)
    target = root / "third_party" / "clamav" / "clamscan.exe"
    if state == "modified":
        target.write_bytes(b"MZ clamscan patched")
    elif state == "not_listed":
        target = root / "third_party" / "clamav" / "freshclam.exe"
        target.write_bytes(b"MZ new")
    elif state == "outside":
        target = tmp_path / "elsewhere" / "clamscan.exe"
        target.parent.mkdir()
        target.write_bytes(b"MZ")
    elif state == "no_manifest":
        (root / "integrity_manifest.json").unlink()
    elif state == "bad_manifest":
        (root / "integrity_manifest.sig").write_bytes(bytes(64))
    verifier = native.IntegrityVerifier(str(root), [str(root / "signatures" / "keys")])
    cpp = verifier.check_component(str(target))
    assert cpp["status"] == state, cpp
    py_ok = _py_component(target, root)
    assert {"verified": True, "no_manifest": None, "outside": None}.get(state, False) == py_ok
    assert cpp["usable"] == (state in ("verified", "no_manifest", "outside"))
    assert verifier.check_component(str(target)) == cpp          # cached result is identical


# ------------------------------------------------------------------------------------------ gk-cli

CLI = [ROOT / "build" / p / "cpp" / "cli" / f"gk-cli{EXE}" for p in ("linux-release", "linux-debug")]
WORKER = [ROOT / "build" / p / "cpp" / "worker" / f"gk-scanworker{EXE}" for p in ("linux-release", "linux-debug")]


@pytest.fixture(scope="module")
def binaries():
    cli = next((c for c in CLI if c.exists()), None)
    worker = next((w for w in WORKER if w.exists()), None)
    if cli is None or worker is None:
        if os.environ.get("GK_REQUIRE_CLI") == "1":
            pytest.fail("gk-cli/gk-scanworker não compilados")
        pytest.skip("gk-cli não compilado (requer Qt 6)")
    return cli, worker


def test_cli_integrity_command(binaries, install):
    cli, _ = binaries
    root, key = install
    run = lambda: subprocess.run([str(cli), "integrity", "--install-dir", str(root)], capture_output=True, text=True,
                                 timeout=120)
    assert run().returncode == 6 and "Manifesto de integridade ausente" in run().stdout
    _build(root, key)
    ok = run()
    assert ok.returncode == 0 and "4 componentes verificados; manifesto assinado." in ok.stdout
    (root / "gk-scanworker.exe").write_bytes(b"tampered")
    bad = run()
    assert bad.returncode == 6 and "modificado: gk-scanworker.exe" in bad.stdout


def test_scan_refuses_a_modified_worker(binaries, tmp_path):
    """A copied installation with a signed manifest scans normally; after gk-scanworker is modified the
    orchestrator refuses to launch it."""
    cli, worker = binaries
    root = tmp_path / "GameKernel"
    root.mkdir()
    shutil.copy(cli, root / cli.name)
    shutil.copy(worker, root / worker.name)
    for rel in ("signatures/yara", "signatures/internal", "signatures/data", "signatures/ioc", "contracts"):
        shutil.copytree(ROOT / rel, root / rel)
    key, pub = _keypair(tmp_path / "private", "release")
    (root / "signatures" / "keys").mkdir()
    shutil.copy(pub, root / "signatures" / "keys" / "release.pub")
    _build(root, key)
    target = tmp_path / "game"
    target.mkdir()
    (target / "a.txt").write_text("nada aqui")

    def scan():
        return subprocess.run([str(root / cli.name), "scan", str(target), "--data-dir", str(tmp_path / "data"),
                               "--quiet", "--json", str(tmp_path / "r.json")], capture_output=True, text=True, timeout=300)

    good = scan()
    assert good.returncode == 0, good.stdout + good.stderr
    import json
    limitations = json.loads((tmp_path / "r.json").read_text())["summary"]["limitations"]
    assert not any("Integridade dos componentes não verificada" in item for item in limitations), limitations
    with open(root / worker.name, "ab") as f:
        f.write(b"\0patched")
    refused = scan()
    assert refused.returncode == 2
    assert "verificação de integridade" in refused.stderr and "gk-scanworker" in refused.stderr
