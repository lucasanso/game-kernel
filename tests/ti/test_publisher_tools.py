"""End to end, as a publisher would do it: gk_keygen → TI preparation → make_update_package
(sign + report) → independent verification → installation by the C++ installer."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.native.native_build import ROOT
from tests.updates.conftest import run_gk_update

TOOLS = ROOT / "tools"


def run(*args, env=None):
    return subprocess.run([sys.executable, *map(str, args)], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=300,
                          env={**os.environ, "PYTHONIOENCODING": "utf-8", **(env or {})})


def test_keygen_refuses_overwrite_and_weak_passwords(tmp_path):
    out = run(TOOLS / "gk_keygen.py", "--out-dir", tmp_path, "--name", "k", "--password-env", "GK_PW",
              env={"GK_PW": "senha-forte-de-teste"})
    assert out.returncode == 0, out.stderr
    assert (tmp_path / "k.key").read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    if os.name != "nt":
        assert oct((tmp_path / "k.key").stat().st_mode & 0o777) == "0o600"
    again = run(TOOLS / "gk_keygen.py", "--out-dir", tmp_path, "--name", "k", "--no-password")
    assert again.returncode == 1 and "não sobrescrevo" in again.stderr


def test_full_publisher_flow(gk_update, components, tmp_path):
    keys = tmp_path / "keys"
    assert run(TOOLS / "gk_keygen.py", "--out-dir", keys, "--name", "release", "--password-env", "GK_PW",
               env={"GK_PW": "senha-forte-de-teste"}).returncode == 0
    package, report = tmp_path / "GameKernel-assinaturas.gkpkg", tmp_path / "relatorio.json"
    built = run(TOOLS / "make_update_package.py", "build", "--key", keys / "release.key", "--password-env", "GK_PW",
                "--version", "2026.11.12.1", "--publisher", "Equipe de testes", "--yara", components["yara"],
                "--ioc", components["ioc"], "--clamav", components["clamav"], "--out", package, "--report", report,
                env={"GK_PW": "senha-forte-de-teste"})
    assert built.returncode == 0, built.stdout + built.stderr
    summary = json.loads(built.stdout)
    assert summary["ok"] and summary["files"] == 5
    rep = json.loads(report.read_text(encoding="utf-8"))
    assert rep["components"]["yara"]["rule_count"] == 1 and rep["components"]["ioc"]["entry_count"] == 2
    assert rep["components"]["clamav"]["signature_count"] == 7
    assert all(v["ok"] for v in rep["native_validation"].values())   # C++ validators ran before signing

    verified = run(TOOLS / "make_update_package.py", "verify", package, "--keys", keys)
    assert verified.returncode == 0 and json.loads(verified.stdout)["ok"]
    code, installed = run_gk_update(gk_update, "install", package, "--root", tmp_path / "sig", "--keys", keys)
    assert code == 0 and installed["ok"], installed

    # Second package with a diff report against the first one.
    (components["yara"] / "extra.yar").write_text(
        (components["yara"] / "gamekernel_test.yar").read_text(encoding="utf-8").replace("GK_Test_Marker", "GK_Extra"),
        encoding="utf-8")
    second, report2 = tmp_path / "v2.gkpkg", tmp_path / "rel2.json"
    built = run(TOOLS / "make_update_package.py", "build", "--key", keys / "release.key", "--password-env", "GK_PW",
                "--version", "2026.11.13.1", "--publisher", "Equipe de testes", "--yara", components["yara"],
                "--out", second, "--report", report2, "--previous", package, "--keys", keys,
                env={"GK_PW": "senha-forte-de-teste"})
    assert built.returncode == 0, built.stderr
    diff = json.loads(report2.read_text(encoding="utf-8"))["diff"]
    assert diff["added"] == ["yara/extra.yar"] and "ioc/local.json" in diff["removed"]


def test_build_refuses_invalid_components(components, tmp_path):
    keys = tmp_path / "keys"
    run(TOOLS / "gk_keygen.py", "--out-dir", keys, "--name", "r", "--no-password")
    (components["yara"] / "broken.yar").write_text("rule x { condition: }", encoding="utf-8")
    built = run(TOOLS / "make_update_package.py", "build", "--key", keys / "r.key", "--no-password",
                "--version", "2026.11.12.1", "--publisher", "t", "--yara", components["yara"],
                "--out", tmp_path / "x.gkpkg")
    assert built.returncode == 1 and "reprovados" in built.stderr
    assert not (tmp_path / "x.gkpkg").exists()


def test_ti_build_ioc_tool(tmp_path):
    h1, h2 = "a" * 64, "b" * 64
    (tmp_path / "bad.txt").write_text(f"{h1}\n{h1.upper()}\n", encoding="utf-8")
    (tmp_path / "good.csv").write_text(f"sha256,verdict,name\n{h2},good,Jogo\n", encoding="utf-8")
    out = tmp_path / "dist" / "local.json"
    proc = run(TOOLS / "ti_build_ioc.py", "--version", "2026.11.12", "--out", out,
               f"{tmp_path / 'bad.txt'}:bad:trojan", tmp_path / "good.csv")
    summary = json.loads(proc.stdout)
    assert proc.returncode == 0 and summary["written_entries"] == 2 and summary["duplicates_merged"] == 1
    entries = {e["sha256"]: e for e in json.loads(out.read_text(encoding="utf-8"))["entries"]}
    assert entries[h1]["category"] == "trojan" and entries[h2]["verdict"] == "good"
    # A conflict aborts unless --prefer-bad.
    (tmp_path / "conflict.csv").write_text(f"sha256,verdict\n{h1},good\n", encoding="utf-8")
    proc = run(TOOLS / "ti_build_ioc.py", "--version", "2026.11.12", "--out", tmp_path / "c.json",
               f"{tmp_path / 'bad.txt'}:bad", tmp_path / "conflict.csv")
    assert proc.returncode == 1 and json.loads(proc.stdout)["conflicts"][0]["sha256"] == h1
    assert not (tmp_path / "c.json").exists()
    proc = run(TOOLS / "ti_build_ioc.py", "--version", "2026.11.12", "--out", tmp_path / "c.json", "--prefer-bad",
               f"{tmp_path / 'bad.txt'}:bad", tmp_path / "conflict.csv")
    assert proc.returncode == 0


def test_source_spec_parsing_handles_drive_letters():
    sys.path.insert(0, str(TOOLS))
    from ti_build_ioc import parse_source

    assert parse_source(r"C:\fontes\a.txt:bad:trojan") == (Path(r"C:\fontes\a.txt"), "bad", "trojan")
    assert parse_source(r"C:\fontes\a.txt:good") == (Path(r"C:\fontes\a.txt"), "good", "")
    assert parse_source(r"C:\fontes\a.csv") == (Path(r"C:\fontes\a.csv"), None, "")
    assert parse_source("rel/a.txt:bad") == (Path("rel/a.txt"), "bad", "")
