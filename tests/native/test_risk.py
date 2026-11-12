"""Risk engine and folder context (cracks, unlockers, mods) — C++ gk::risk via gk_native."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from gamekernel.core.models import FileResult

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = ROOT / "signatures" / "data" / "game_components.json"
CATALOG = ROOT / "contracts" / "threat_catalog.json"


def _file(path: str, *, evidences=(), file_type="pe_dll", version_info=None, text_head=None, status="complete",
          reasons=()) -> dict:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].rsplit("::", 1)[-1]
    doc = FileResult(path=path, name=name, directory=path.rsplit("/", 1)[0], extension="." + name.rsplit(".", 1)[-1].lower(),
                     size=100, sha256="0" * 64, file_type=file_type).to_dict()
    doc["features"]["is_pe"] = file_type.startswith("pe_")
    doc["features"]["version_info"] = version_info or {}
    doc["features"]["text_head"] = text_head
    doc["status"] = status
    doc["status_reasons"] = list(reasons)
    doc["evidences"] = [_evidence(*e) for e in evidences]
    return doc


def _evidence(rule_id, severity, source="heuristic", category="obfuscation", confidence="MEDIUM", verdict=None, tags=()):
    details = {"verdict": verdict} if verdict else {}
    return {"rule_id": rule_id, "title": rule_id, "source": source, "category": category, "severity": severity,
            "confidence": confidence, "description": "", "engine": "test", "locations": [], "details": details,
            "fp_note": "nota de falso positivo", "tags": list(tags), "adjusted_severity": None, "adjustment_reason": ""}


def _assess(native, files: list[dict]) -> dict[str, dict]:
    out = native.risk_assess(files, COMPONENTS, CATALOG)
    for doc in out:
        assert FileResult.from_dict(doc).to_dict() == doc   # contract with the Python model
    return {d["name"]: d for d in out}


def test_unknown_clean_file(native):
    r = _assess(native, [_file("/g/Game.exe", file_type="pe_exe")])["Game.exe"]
    assert r["classification"] == "unknown" and r["risk"] == "NONE" and r["crack_status"] == "none"
    assert any("não prova" in line for line in r["explanation"])
    assert not r["possible_false_positive"] and r["recommendations"] == []


def test_malware_by_yara_verdict_and_test_file(native):
    eicar = _file("/g/eicar.com", file_type="data",
                  evidences=[("YARA.GK_Test_EICAR", "HIGH", "yara", "test_file", "HIGH", "test")])
    r = _assess(native, [eicar])["eicar.com"]
    assert r["classification"] == "malware" and r["risk"] == "HIGH" and r["primary_category"] == "test_file"
    assert any("teste antivírus" in line for line in r["explanation"])
    assert not r["possible_false_positive"]


def test_heuristic_only_is_suspicious_with_possible_false_positive(native):
    f = _file("/g/tool.exe", file_type="pe_exe",
              evidences=[("HEUR.Injection.RemoteThread", "MEDIUM", "heuristic", "process_injection")])
    r = _assess(native, [f])["tool.exe"]
    assert r["classification"] == "suspicious" and r["risk"] == "MEDIUM"
    assert r["possible_false_positive"] and any("Falso positivo" in line for line in r["explanation"])
    assert r["recommendations"] and any("sandbox" in rec for rec in r["recommendations"])


def test_goldberg_recognised_and_expected_traits_mitigated(native):
    files = [
        _file("/g/Game/steam_api64.dll", evidences=[("PE.MinimalImports", "LOW", "static"), ("PE.Packer.UPX", "LOW", "static")]),
        _file("/g/Game/steam_settings/configs.user.ini", file_type="text"),
        _file("/g/Game/Game.exe", file_type="pe_exe"),
    ]
    r = _assess(native, files)
    api = r["steam_api64.dll"]
    assert api["crack_status"] == "recognized_clean" and api["classification"] == "modified"
    assert api["risk"] == "INFO"
    assert all(e["adjusted_severity"] == "INFO" for e in api["evidences"] if e["rule_id"].startswith("PE."))
    assert any(e["rule_id"] == "CONTEXT.Component.goldberg" for e in api["evidences"])
    assert r["Game.exe"]["crack_status"] == "none"   # not a target of the component


def test_crack_with_threat_is_never_mitigated(native):
    files = [
        _file("/g/Game/steam_api64.dll", evidences=[
            ("HEUR.Stealer.Profile", "HIGH", "heuristic", "password_stealer"),
            ("PE.MinimalImports", "LOW", "static")]),
        _file("/g/Game/steam_emu.ini", file_type="text", text_head="[Settings] ; CODEX"),
    ]
    r = _assess(native, files)["steam_api64.dll"]
    assert r["classification"] == "suspicious" and r["crack_status"] == "suspicious" and r["risk"] == "HIGH"
    stealer = next(e for e in r["evidences"] if e["rule_id"] == "HEUR.Stealer.Profile")
    assert stealer["adjusted_severity"] is None
    assert any("CODEX" in line for line in r["explanation"])


def test_crack_with_malware_detection(native):
    files = [
        _file("/g/G/steam_api64.dll", evidences=[("YARA.GK_RAT_Quasar", "CRITICAL", "yara", "rat", "HIGH", "malware")]),
        _file("/g/G/cream_api.ini", file_type="text"),
        _file("/g/G/steam_api64_o.dll"),
    ]
    r = _assess(native, files)["steam_api64.dll"]
    assert r["classification"] == "malware" and r["crack_status"] == "malware" and r["risk"] == "CRITICAL"
    assert any(e["rule_id"] == "CONTEXT.ReplacedDll" for e in r["evidences"])


def test_reshade_by_version_info_is_a_mod(native):
    f = _file("/g/G/dxgi.dll", version_info={"ProductName": "ReShade", "CompanyName": "crosire"},
              evidences=[("PE.DllProxy", "INFO", "static", "dll_hijacking"), ("PE.HighEntropyCode", "LOW", "static")])
    r = _assess(native, [f])["dxgi.dll"]
    assert r["classification"] == "unknown" and r["crack_status"] == "none" and r["risk"] == "INFO"
    assert any(e["rule_id"] == "CONTEXT.Component.reshade" for e in r["evidences"])


def test_unrecognised_dll_proxy_is_modified(native):
    f = _file("/g/G/version.dll", evidences=[("PE.DllProxy", "INFO", "static", "dll_hijacking")])
    r = _assess(native, [f])["version.dll"]
    assert r["classification"] == "modified" and r["crack_status"] == "modified_no_threat" and r["risk"] == "LOW"
    assert any(e["rule_id"] == "CONTEXT.UnrecognizedProxy" for e in r["evidences"])


def test_crack_like_names_and_folders(native):
    files = [_file("/g/Tools/Game_Trainer.exe", file_type="pe_exe"),
             _file("/g/G/CODEX/patchme.exe", file_type="pe_exe"),
             _file("/g/G/GamePatch.exe", file_type="pe_exe"),
             _file("/g/G/skse64_loader.exe", file_type="pe_exe")]
    r = _assess(native, files)
    assert r["Game_Trainer.exe"]["crack_status"] == "unknown" and r["Game_Trainer.exe"]["classification"] == "modified"
    assert r["patchme.exe"]["crack_status"] == "unknown"
    assert r["GamePatch.exe"]["crack_status"] == "none"        # official patchers are not cracks
    assert r["skse64_loader.exe"]["crack_status"] == "none"    # mod loader, recognised as a mod
    assert r["skse64_loader.exe"]["classification"] == "unknown"


def test_incomplete_analysis_is_inconclusive(native):
    files = [_file("/g/G/crack/keygen.exe", file_type="pe_exe", status="partial", reasons=["tempo limite do YARA excedido"])]
    r = _assess(native, files)["keygen.exe"]
    assert r["classification"] == "inconclusive" and r["crack_status"] == "insufficient"
    assert any("tempo limite" in line for line in r["explanation"])


def test_archive_members_share_folder_context(native):
    files = [
        _file("/d/Repack.zip::Game/steam_api64.dll"),
        _file("/d/Repack.zip::Game/steam_settings/force_account_name.txt", file_type="text"),
    ]
    files[0]["container"] = files[1]["container"] = "/d/Repack.zip"
    r = _assess(native, files)["steam_api64.dll"]
    assert r["crack_status"] == "recognized_clean"


def test_glob_matching(native):
    assert native.glob_match("fg-*.bin", "FG-01.BIN")
    assert native.glob_match("*.unpacked.exe", "Game.exe.unpacked.exe")
    assert native.glob_match("skse64_*.dll", "skse64_1_6_640.dll")
    assert not native.glob_match("*.asi", "plugin.asi.txt")
    assert native.glob_match("a?c", "abc") and not native.glob_match("a?c", "ac")


def test_data_files_are_valid_and_current(native, tmp_path):
    result = subprocess.run([sys.executable, str(ROOT / "tools" / "core_gen_threat_catalog.py"), "--check"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    bad = tmp_path / "components.json"
    bad.write_text(json.dumps({"format": "outro"}))
    with pytest.raises(native.GkError):
        native.risk_assess([_file("/g/a.exe")], bad, CATALOG)


def test_end_to_end_with_analysis(native, tmp_path):
    rules = native.AnalysisRules.load([str(ROOT / "signatures" / "yara")],
                                      str(ROOT / "signatures" / "internal" / "indicators.yar"))
    data = (b"MZ" + b"\0" * 64 + b"\\Login Data\0encrypted_key\0CryptUnprotectData\0"
            b"https://discord.com/api/webhooks/123456789012/xyz\0")
    analysed = native.analyze_bytes(data, "steam_api64.dll", path="/g/G/steam_api64.dll", rules=rules)["result"]
    ini = _file("/g/G/steam_emu.ini", file_type="text", text_head="RUNE")
    r = _assess(native, [analysed, ini])["steam_api64.dll"]
    assert r["classification"] == "suspicious" and r["crack_status"] == "suspicious"
    assert r["primary_category"] == "password_stealer" and r["risk"] == "HIGH"
