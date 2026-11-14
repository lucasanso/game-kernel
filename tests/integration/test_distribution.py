"""Product distribution (tools/make_distribution.py, installer/gamekernel.iss).

Two layers:
* assembly rules, run everywhere with stand-in binaries: layout, integrity manifest, refusal of private keys,
  networking DLLs, conflicting DLLs and stray portable flags, portable ZIP;
* the *installed product* (CI on Windows sets GK_INSTALLED_DIR after a silent install, and again for the
  extracted portable ZIP): manifest intact, no networking import in any shipped binary, the installed frozen
  helper loads every service, and the installed gk-cli finds an EICAR file generated here with the bundled
  signatures, after which the installed helper writes the forensic report from that same database.
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
    return {"app": app, "bins": [cli, worker, update], "helper": helper, "crt": crt, "tmp": tmp_path}


def _plan(parts, **kw) -> MD.Plan:
    return MD.Plan(out=parts["tmp"] / "dist" / "GameKernel", app=parts["app"], bins=parts["bins"],
                   helper=parts["helper"], crt_dir=parts["crt"], deploy_qt=False, **kw)


def test_layout_and_manifest(parts):
    summary = MD.build(_plan(parts))
    out = Path(summary["folder"])
    assert summary["version"] == MD.product_version()
    for rel in (f"GameKernel{EXE}", f"gk-cli{EXE}", f"gk-scanworker{EXE}", f"gk-update{EXE}", "libsodium.dll",
                "vcruntime140.dll", f"helper/gk-helper{EXE}", "helper/_internal/base_library.zip",
                "signatures/internal/indicators.yar", "signatures/data/game_components.json",
                "signatures/yara/gk_test_files.yar", "contracts/threat_catalog.json", "docs/USAGE.md", "docs/PRIVACY.md", "docs/LIMITATIONS.md"):
        assert (out / rel).is_file(), rel
    assert not (out / "portable.flag").exists() and not (out / "signatures" / "keys").exists()
    assert MD.verify_manifest(out) == []
    lines = (out / MD.MANIFEST).read_text(encoding="utf-8").splitlines()
    assert len(lines) == summary["files"] and all("\\" not in line for line in lines)


def test_manifest_detects_tampering_missing_and_extra_files(parts):
    out = Path(MD.build(_plan(parts))["folder"])
    (out / f"gk-cli{EXE}").write_bytes(b"patched")
    (out / "docs" / "PRIVACY.md").unlink()
    (out / "intruso.dll").write_bytes(b"x")
    (out / "unins000.exe").write_bytes(b"uninstaller")
    problems = MD.verify_manifest(out, ignore=("unins000.exe",))
    assert problems == ["ausente: docs/PRIVACY.md", f"alterado: gk-cli{EXE}", "não previsto: intruso.dll"]


def test_release_key_is_checked(parts):
    private = Ed25519PrivateKey.generate()
    pub = parts["tmp"] / "release.pub"
    pub.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
    out = Path(MD.build(_plan(parts, release_key=pub))["folder"])
    assert (out / "signatures" / "keys" / "release.pub").read_bytes() == pub.read_bytes()

    leaked = parts["tmp"] / "leaked.pub"
    leaked.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    with pytest.raises(MD.DistributionError, match="PRIVADA"):
        MD.build(_plan(parts, release_key=leaked))


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


def test_portable_zip(parts):
    out = Path(MD.build(_plan(parts))["folder"])
    zip_path = parts["tmp"] / "GameKernel-portable.zip"
    entries = MD.make_portable_zip(out, zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        assert len(names) == entries and "GameKernel/portable.flag" in names
        assert f"GameKernel/GameKernel{EXE}" in names and "GameKernel/MANIFEST.sha256" in names
        extracted = parts["tmp"] / "portable"
        zf.extractall(extracted)
    # the portable flag is outside the manifest; the program folder stays verifiable
    assert MD.verify_manifest(extracted / "GameKernel", ignore=("portable.flag",)) == []
    (out / f"gk-cli{EXE}").write_bytes(b"patched")
    with pytest.raises(MD.DistributionError, match="manifesto"):
        MD.make_portable_zip(out, zip_path)


def test_cli_verify_and_version(parts, capsys):
    out = Path(MD.build(_plan(parts))["folder"])
    assert MD.main(["--verify", str(out)]) == 0
    (out / "docs" / "USAGE.md").write_text("alterado")
    assert MD.main(["--verify", str(out)]) == 1
    assert MD.main(["--print-version"]) == 0
    assert capsys.readouterr().out.strip().splitlines()[-1] == MD.product_version()


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
def test_installed_files_match_the_manifest():
    assert MD.verify_manifest(_installed(), ignore=("unins000.exe", "unins000.dat", "unins000.msg", "portable.flag", "data")) == []


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
