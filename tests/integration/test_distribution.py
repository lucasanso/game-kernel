"""Product distribution (tools/make_distribution.py, installer/gamekernel.iss).

Two layers:
* assembly rules, run everywhere with stand-in binaries: layout, signed integrity manifest (Agent A's M10
  format, verified with Agent A's own checker), refusal of private keys, networking DLLs, conflicting DLLs and
  stray portable flags, portable ZIP;
* the *installed product* (CI on Windows sets GK_INSTALLED_DIR after a silent install, and again for the
  extracted portable ZIP): `gk-cli integrity` confirms the installation, no networking import in any shipped
  binary, the installed frozen helper loads every service, and the installed gk-cli finds an EICAR file
  generated here with the bundled signatures, after which the installed helper writes the forensic report
  from that same database.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gamekernel import app_paths, crypto_utils
from gamekernel.core import integrity
from tools import make_distribution as MD

ROOT = Path(__file__).resolve().parents[2]
EXE = ".exe" if sys.platform == "win32" else ""


# ------------------------------------------------------------------------------- assembly (everywhere)
def _component(folder: Path, name: str, payload: bytes, dlls: dict[str, bytes] | None = None) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    binary = folder / name
    binary.write_bytes(payload)
    for dll, data in (dlls or {}).items():
        (folder / dll).write_bytes(data)
    return binary


@pytest.fixture
def parts(tmp_path):
    app = _component(tmp_path / "app", f"GameKernel{EXE}", b"app", {"libsodium.dll": b"sodium-1"})
    cli = _component(tmp_path / "core", f"gk-cli{EXE}", b"cli", {"libsodium.dll": b"sodium-1"})
    worker = _component(tmp_path / "core", f"gk-scanworker{EXE}", b"worker")
    update = _component(tmp_path / "upd", f"gk-update{EXE}", b"update")
    helper = tmp_path / "gk-helper"
    _component(helper, f"gk-helper{EXE}", b"helper")
    _component(helper / "_internal", "base_library.zip", b"zip")
    crt = tmp_path / "crt"
    _component(crt, "vcruntime140.dll", b"crt")
    return {"app": app, "bins": [cli, worker, update], "helper": helper, "crt": crt, "tmp": tmp_path,
            "key": Ed25519PrivateKey.generate()}


def _plan(parts, signed: bool = True, **kw) -> MD.Plan:
    return MD.Plan(out=parts["tmp"] / "dist" / "GameKernel", app=parts["app"], bins=parts["bins"],
                   helper=parts["helper"], crt_dir=parts["crt"], deploy_qt=False,
                   signer=parts["key"] if signed else None, **kw)


def _agent_a_check(out: Path, monkeypatch) -> integrity.IntegrityReport:
    """Agent A's Python checker, trusting the keys shipped in ``out`` (as the installed product does)."""
    monkeypatch.setattr(app_paths, "trusted_keys_dir", lambda: out / "signatures" / "keys")
    integrity.clear_caches()
    return integrity.check_installation(out)


def test_layout_and_signed_manifest(parts, monkeypatch):
    summary = MD.build(_plan(parts))
    out = Path(summary["folder"])
    assert summary["version"] == MD.product_version() and summary["signed"] is True
    assert summary["key_id"] == crypto_utils.key_id(parts["key"].public_key())
    for rel in (f"GameKernel{EXE}", f"gk-cli{EXE}", f"gk-scanworker{EXE}", f"gk-update{EXE}", "libsodium.dll",
                "vcruntime140.dll", f"helper/gk-helper{EXE}", "helper/_internal/base_library.zip",
                "signatures/internal/indicators.yar", "signatures/data/game_components.json",
                "signatures/yara/gk_test_files.yar", "contracts/threat_catalog.json", "docs/USAGE.md",
                "docs/PRIVACY.md", "docs/LIMITATIONS.md", MD.RELEASE_PUB, integrity.MANIFEST_NAME,
                integrity.SIGNATURE_NAME):
        assert (out / rel).is_file(), rel
    assert not (out / "portable.flag").exists()
    manifest = json.loads((out / integrity.MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["format"] == "gamekernel-integrity" and manifest["version"] == summary["version"]
    assert f"gk-scanworker{EXE}" in manifest["files"] and MD.RELEASE_PUB in manifest["files"]
    assert len(manifest["files"]) == summary["files"]
    assert MD.manifest_problems(out) == []
    report = _agent_a_check(out, monkeypatch)
    assert report.ok and report.signature_valid is True and report.signer_key_id == summary["key_id"]


def test_tampering_is_detected_by_both_checkers(parts, monkeypatch):
    out = Path(MD.build(_plan(parts))["folder"])
    (out / f"gk-cli{EXE}").write_bytes(b"patched")
    (out / "docs" / "PRIVACY.md").unlink()
    (out / "intruso.dll").write_bytes(b"x")
    assert MD.manifest_problems(out) == ["ausente: docs/PRIVACY.md", f"alterado: gk-cli{EXE}",
                                         "não previsto: intruso.dll"]
    report = _agent_a_check(out, monkeypatch)
    assert not report.ok and report.modified == [f"gk-cli{EXE}"] and report.missing == ["docs/PRIVACY.md"]


def test_manifest_signed_by_another_key_is_rejected(parts, monkeypatch):
    out = Path(MD.build(_plan(parts))["folder"])
    raw = (out / integrity.MANIFEST_NAME).read_bytes()
    (out / integrity.SIGNATURE_NAME).write_bytes(crypto_utils.sign(Ed25519PrivateKey.generate(), raw))
    assert MD.manifest_problems(out) == ["assinatura do manifesto não confere com as chaves distribuídas"]
    report = _agent_a_check(out, monkeypatch)
    assert not report.ok and report.signature_valid is False


def test_unsigned_local_build(parts, monkeypatch):
    out = Path(MD.build(_plan(parts, signed=False))["folder"])
    assert (out / integrity.MANIFEST_NAME).is_file() and not (out / integrity.SIGNATURE_NAME).exists()
    assert not (out / MD.RELEASE_PUB).exists() and MD.manifest_problems(out) == []
    report = _agent_a_check(out, monkeypatch)
    assert report.ok and report.signature_valid is None and "sem assinatura" in report.detail


def test_signing_key_loading(parts, tmp_path):
    pem = parts["key"].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())
    (tmp_path / "release.key").write_bytes(pem)
    loaded = MD.load_signing_key(tmp_path / "release.key", None)
    assert crypto_utils.key_id(loaded.public_key()) == crypto_utils.key_id(parts["key"].public_key())
    (tmp_path / "release.pub").write_bytes(parts["key"].public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(MD.DistributionError, match="chave privada"):
        MD.load_signing_key(tmp_path / "release.pub", None)       # a public key cannot sign


def test_private_key_material_is_refused(parts):
    leaked = parts["key"].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
    (parts["helper"] / "_internal" / "chave.pem").write_bytes(leaked)
    with pytest.raises(MD.DistributionError, match="chave privada"):
        MD.build(_plan(parts))


@pytest.mark.parametrize("dll", ["Qt6Network.dll", "winhttp.dll"])
def test_networking_dll_is_refused(parts, dll):
    (parts["app"].parent / dll).write_bytes(b"net")
    with pytest.raises(MD.DistributionError, match="rede"):
        MD.build(_plan(parts))


def test_conflicting_dlls_are_refused(parts):
    (parts["bins"][0].parent / "libsodium.dll").write_bytes(b"sodium-2")
    with pytest.raises(MD.DistributionError, match="conflito: libsodium.dll"):
        MD.build(_plan(parts))


def test_missing_core_binary_is_refused(parts):
    parts["bins"] = parts["bins"][:1]
    with pytest.raises(MD.DistributionError, match="gk-scanworker"):
        MD.build(_plan(parts))


def test_unrelated_output_folder_is_never_deleted(parts):
    out = parts["tmp"] / "dist" / "GameKernel"
    out.mkdir(parents=True)
    (out / "importante.txt").write_text("não apague")
    with pytest.raises(MD.DistributionError, match="nada foi apagado"):
        MD.build(_plan(parts))
    assert (out / "importante.txt").exists()


def test_portable_zip(parts, monkeypatch):
    out = Path(MD.build(_plan(parts))["folder"])
    zip_path = parts["tmp"] / "GameKernel-portable.zip"
    entries = MD.make_portable_zip(out, zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        assert len(names) == entries and "GameKernel/portable.flag" in names
        assert f"GameKernel/GameKernel{EXE}" in names and f"GameKernel/{integrity.MANIFEST_NAME}" in names
        extracted = parts["tmp"] / "portable"
        zf.extractall(extracted)
    # portable.flag is not a shipped program file: the extracted folder still checks out (data/ is excluded too)
    (extracted / "GameKernel" / "data").mkdir()
    (extracted / "GameKernel" / "data" / "settings.json").write_text("{}")
    assert _agent_a_check(extracted / "GameKernel", monkeypatch).ok
    (out / f"gk-cli{EXE}").write_bytes(b"patched")
    with pytest.raises(MD.DistributionError, match="manifesto"):
        MD.make_portable_zip(out, zip_path)


def test_cli_requires_an_explicit_signing_choice(parts, capsys):
    common = ["--app", str(parts["app"]), *sum((["--bin", str(b)] for b in parts["bins"]), []),
              "--out", str(parts["tmp"] / "cli-out")]
    with pytest.raises(SystemExit):
        MD.main(common)                                   # neither --key nor --unsigned
    assert "--unsigned" in capsys.readouterr().err
    assert MD.main(["--print-version"]) == 0
    assert capsys.readouterr().out.strip().splitlines()[-1] == MD.product_version()


def test_ui_and_core_share_the_product_version():
    """The installer, the UI and VERSIONINFO use cpp/app's version; the core (gk::kVersion, gk-cli --version)
    uses the root project's. A release with two different numbers would be confusing and unauditable."""
    import re
    root = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    core = re.search(r"project\(GameKernel VERSION (\d+\.\d+\.\d+)", root)
    assert core and core.group(1) == MD.product_version()


def test_installer_script_matches_the_distribution():
    iss = (ROOT / "installer" / "gamekernel.iss").read_text(encoding="utf-8-sig")
    assert '#define AppExe "GameKernel.exe"' in iss
    assert "SetupIconFile=..\\assets\\gamekernel.ico" in iss and (ROOT / "assets" / "gamekernel.ico").is_file()
    assert 'Source: "{#SourceDir}\\*"' in iss and "recursesubdirs" in iss
    # offline installer: no download/URL directives, and user data is never deleted on uninstall
    for forbidden in ("http://", "https://", "[UninstallDelete]", "DownloadTemporaryFile", "idp."):
        assert forbidden not in iss, forbidden


# ----------------------------------------------------------------------------- installed product (CI)
INSTALLED = os.environ.get("GK_INSTALLED_DIR")
installed = pytest.mark.skipif(not INSTALLED, reason="GK_INSTALLED_DIR não definido (CI Windows após instalar)")
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode()


def _installed() -> Path:
    return Path(INSTALLED).resolve()


@installed
def test_installed_product_integrity_is_confirmed_by_the_core(tmp_path):
    """The product's own checker (gk-cli integrity, gk::integrity) over the installed folder."""
    out = tmp_path / "integrity.json"
    proc = subprocess.run([str(_installed() / f"gk-cli{EXE}"), "integrity", "--install-dir", str(_installed()),
                           "--json", str(out)], capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=600)
    report = json.loads(out.read_text(encoding="utf-8"))
    assert proc.returncode == 0 and report["ok"] and report["manifest_present"], (proc.stdout, report)
    if os.environ.get("GK_EXPECT_SIGNED") == "1":
        shipped = crypto_utils.load_public_key((_installed() / MD.RELEASE_PUB).read_bytes())
        assert report["signature_valid"] is True and report["signer_key_id"] == crypto_utils.key_id(shipped)


@installed
@pytest.mark.skipif(sys.platform != "win32", reason="binários PE só no Windows")
def test_no_installed_binary_imports_network_code():
    from tests.ui.test_app_offline_imports import _pe_violations

    binaries = [p for p in _installed().rglob("*") if p.suffix.lower() in (".exe", ".dll", ".pyd")
                and not p.name.lower().startswith("unins")]
    assert len(binaries) > 20
    problems = [v for p in binaries if not p.is_relative_to(_installed() / "helper") for v in _pe_violations(p)]
    assert problems == [], problems


@installed
def test_installed_scan_and_report_end_to_end(tmp_path):
    from gamekernel.helper.client import HelperClient, sanitized_environment
    from gamekernel.helper.services import registry

    game = tmp_path / "Jogo"
    game.mkdir()
    (game / "leia_eicar.com").write_bytes(EICAR)
    (game / "config.ini").write_text("[video]\nresolution=1920x1080\n", encoding="utf-8")
    data = tmp_path / "dados"
    report_json = tmp_path / "varredura.json"
    proc = subprocess.run([str(_installed() / f"gk-cli{EXE}"), "scan", str(game), "--data-dir", str(data),
                           "--json", str(report_json), "--quiet"], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=600)
    assert proc.returncode == 3, proc.stderr                       # threat found by the installed core
    scan = json.loads(report_json.read_text(encoding="utf-8"))
    assert not any("integridade" in w.lower() for w in scan["summary"].get("warnings", [])), scan["summary"]
    results = {r["name"]: r for r in scan["results"]}
    assert results["leia_eicar.com"]["classification"] == "malware"
    assert "yara" in {e["source"] for e in results["leia_eicar.com"]["evidences"]}   # bundled rules were found

    helper = _installed() / "helper" / f"gk-helper{EXE}"
    with HelperClient([str(helper)], env=sanitized_environment(data), cwd=helper.parent) as client:
        info = client.call("system.info")
        assert info["frozen"] is True and info["netguard"] is True and info["unavailable_services"] == {}
        assert {svc.method for svc in registry()} <= set(info["methods"])
        out = client.call("reports.generate", {"scan_id": scan["summary"]["scan_id"], "formats": ["html", "json"],
                                               "output_dir": str(tmp_path), "db_path": str(data / "gamekernel.db")},
                          timeout=300)
    html = next(Path(f["path"]) for f in out["files"] if f["path"].endswith(".html"))
    assert "leia_eicar.com" in html.read_text(encoding="utf-8")
