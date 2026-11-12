"""Forensic reports: content (spec §16), crack reports, privacy, escaping, read-only DB, helper service."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

import pytest

from gamekernel.reports import engine as RE
from gamekernel.reports.render_html import render_html
from gamekernel.reports.render_pdf import render_pdf
from gamekernel.helper.client import HelperClient, HelperError, sanitized_environment

from tests.corpus import sample_scan

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def scan(db):
    return db, sample_scan.build(db)


def _report(db, scan_id, **opts):
    store = RE.ReadOnlyStore(db.path)
    try:
        return RE.build_report(store, scan_id, RE.ReportOptions(**opts))
    finally:
        store.close()


def test_report_contains_every_required_section(scan):
    db, scan_id = scan
    r = _report(db, scan_id)
    assert r["format"] == "gamekernel-report" and r["format_version"] == 1
    # 1 computer, 2 targets, 3 date/duration
    assert r["computer"]["os"]["system"] and r["computer"]["cpu"]["logical_cores"] >= 1
    assert r["scan"]["targets"] and r["scan"]["started_at"] and r["scan"]["duration_seconds"] >= 0
    # 4/5/6 counts and files not examined, with reasons
    assert r["counts"]["files_found"] == 15 and r["counts"]["files_analyzed"] == 13
    reasons = {n["name"]: n["reasons"] for n in r["not_examined"]}
    assert reasons["locked.pak"] == ["Permissão negada"]
    assert "huge.iso" in reasons and "setup.7z" in reasons
    # 7/8 threats and suspicious
    assert [t["name"] for t in r["threats"]] == ["eicar_test.com"]
    assert {s["name"] for s in r["suspicious"]} >= {"launcher_patch.exe", "payload.exe"}
    assert [p["classification"] for p in r["pua"]] == ["pua"]
    # 9-13 evidence with locations, full path, SHA-256, risk, explanation
    stealer = next(s for s in r["suspicious"] if s["name"] == "launcher_patch.exe")
    assert len(stealer["sha256"]) == 64 and stealer["path"].endswith("launcher_patch.exe")
    assert stealer["risk"] == "HIGH" and stealer["explanation"]
    yara_ev = next(e for e in stealer["evidences"] if e["source"] == "yara")
    loc = yara_ev["locations"][0]
    assert loc["section"] == ".rdata" and loc["offset"] == 0x1A2C0 and loc["rva"] == 0x1C2C0
    assert "offset 0x1A2C0" in loc["summary"] and "RVA 0x1C2C0" in loc["summary"]
    assert stealer["threat_info"]["data_at_risk"] and stealer["possible_false_positive"]
    heur = next(e for e in stealer["evidences"] if e["source"] == "heuristic")
    assert heur["generic_indicator"] is True and heur["fp_note"]
    # 14/15 recommendations and limitations
    assert any("quarentena" in x for x in r["recommendations"])
    assert any("desatualizadas" in x for x in r["recommendations"])   # stale signatures in the summary
    assert any("não garante" in x for x in r["limitations"])
    assert "ClamAV executado sem as bases oficiais (somente assinaturas locais)." in r["limitations"]


def test_archive_member_points_to_physical_container(scan):
    db, scan_id = scan
    member = next(s for s in _report(db, scan_id)["suspicious"] if s["name"] == "payload.exe")
    assert member["physical_file"].endswith("extras.zip")
    assert member["member_path"] == "bin/payload.exe"


def test_individual_crack_reports(scan):
    db, scan_id = scan
    cracks = {c["name"]: c for c in _report(db, scan_id)["cracks"]}
    ok, bad = cracks["steam_api64.dll"], cracks["crack/Game.exe"]
    assert ok["modification_types"] == ["Emulador de Steam"]
    assert ok["potential_risks"] == [] and "não é garantia" in ok["crack_recommendation"]
    assert "Executável do jogo modificado (patch de DRM)" in bad["modification_types"]
    from gamekernel.core import threat_catalog
    from gamekernel.core.models import ThreatCategory
    assert bad["potential_risks"] == [threat_catalog.info(ThreatCategory.PERSISTENCE).label]
    assert bad["threat_evidence_count"] == 1 and "Não execute" in bad["crack_recommendation"]
    for c in cracks.values():
        assert len(c["sha256"]) == 64 and c["path"]


def test_username_and_hostname_are_redacted_by_default(scan, monkeypatch):
    db, scan_id = scan
    monkeypatch.setenv("USERNAME", sample_scan.USER)
    text = json.dumps(_report(db, scan_id), ensure_ascii=False)
    assert sample_scan.USER not in text
    assert "C:\\\\Users\\\\<usuário>\\\\Downloads" in text
    assert "hostname" not in _report(db, scan_id)["computer"]


def test_opt_in_keeps_username_and_hostname(scan, monkeypatch):
    db, scan_id = scan
    monkeypatch.setenv("USERNAME", sample_scan.USER)
    r = _report(db, scan_id, redact_username=False, include_hostname=True)
    assert sample_scan.USER in json.dumps(r, ensure_ascii=False)
    assert r["computer"]["hostname"]


def test_redactor_only_replaces_whole_path_segments():
    red = RE.Redactor(["ana"], None)
    assert red.text(r"C:\Users\Ana\Games\banana.exe") == r"C:\Users\<usuário>\Games\banana.exe"
    assert red.text("/home/ana/x") == "/home/<usuário>/x"
    assert red.text("ana") == "ana"   # not a path segment


def test_include_clean_lists_clean_files(scan):
    db, scan_id = scan
    assert _report(db, scan_id)["clean_files"] == []
    clean = _report(db, scan_id, include_clean=True)["clean_files"]
    assert len(clean) == 6 and all(len(c["sha256"]) == 64 for c in clean)
    assert any(c["path"].endswith("ゲーム.exe") for c in clean)


def test_html_is_self_contained_and_escaped(scan):
    db, scan_id = scan
    html = render_html(_report(db, scan_id))
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "<script" not in html.lower()
    assert "&lt;script&gt;alert(1)&lt;/script&gt;.dll" in html
    assert not re.search(r"\b(src|href)\s*=", html, re.I)
    assert "https://" not in html and "http://" not in html
    for title in ("Informações gerais do computador", "Arquivos não examinados", "Ameaças detectadas",
                  "Relatório individual de cracks", "Recomendações", "Limitações da análise"):
        assert title in html
    assert "ゲーム.exe" not in html   # clean file: listed only with include_clean
    assert "ゲーム.exe" in render_html(_report(db, scan_id, include_clean=True))


def test_pdf_is_generated_with_unicode_font(scan):
    db, scan_id = scan
    data, warnings = render_pdf(_report(db, scan_id, include_clean=True))
    assert data.startswith(b"%PDF-") and data.rstrip().endswith(b"%%EOF")
    assert len(data) > 5000 and data.count(b"/Type /Page") >= 2
    if Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf").exists():
        assert warnings == []


def test_generate_writes_all_formats_atomically(scan, tmp_path):
    db, scan_id = scan
    out = tmp_path / "reports"
    out.mkdir()
    result = RE.generate(db.path, scan_id, ["json", "html", "pdf"], out)
    assert [f["format"] for f in result["files"]] == ["json", "html", "pdf"]
    for f in result["files"]:
        data = Path(f["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == f["sha256"] and len(data) == f["size"]
    assert not list(out.glob(".gk-report-*"))   # no temporary leftovers
    loaded = json.loads(Path(result["files"][0]["path"]).read_text(encoding="utf-8"))
    assert loaded["scan"]["id"] == scan_id and result["counts"]["threats"] == 1


def test_database_is_opened_read_only(scan, tmp_path):
    db, scan_id = scan
    store = RE.ReadOnlyStore(db.path)
    with pytest.raises(sqlite3.OperationalError):
        store.conn.execute("DELETE FROM scans")
    store.close()
    assert db.get_scan(scan_id) is not None


def test_missing_database_is_not_created(tmp_path):
    missing = tmp_path / "nope.db"
    with pytest.raises(RE.ReportError) as exc:
        RE.ReadOnlyStore(missing)
    assert exc.value.code == "not_found" and not missing.exists()


@pytest.mark.parametrize("formats, outdir, code", [
    (["docx"], None, "invalid_params"),
    ([], None, "invalid_params"),
    (["html"], "relative/dir", "invalid_params"),
])
def test_generate_rejects_bad_arguments(scan, tmp_path, formats, outdir, code):
    db, scan_id = scan
    with pytest.raises(RE.ReportError) as exc:
        RE.generate(db.path, scan_id, formats, outdir or tmp_path)
    assert exc.value.code == code


def test_unknown_scan(scan, tmp_path):
    db, _ = scan
    with pytest.raises(RE.ReportError) as exc:
        RE.generate(db.path, 999, ["json"], tmp_path)
    assert exc.value.code == "not_found"


# ---------------------------------------------------------------------------- through the helper process
@pytest.fixture
def helper(isolated_data_dir):
    client = HelperClient([sys.executable, "-I", str(ROOT / "gamekernel" / "helper" / "entry.py")],
                          env=sanitized_environment(isolated_data_dir), cwd=ROOT)
    client.start()
    yield client
    client.close()


def test_helper_generates_reports_with_progress(scan, helper, tmp_path):
    db, scan_id = scan
    events = []
    result = helper.call("reports.generate", {"scan_id": scan_id, "formats": ["json", "html", "pdf"],
                                              "output_dir": str(tmp_path), "db_path": str(db.path)},
                         timeout=120, on_event=lambda name, data: events.append(data["stage"]))
    assert events == ["load", "json", "html", "pdf"]
    assert {Path(f["path"]).suffix for f in result["files"]} == {".json", ".html", ".pdf"}
    assert all(Path(f["path"]).exists() for f in result["files"])
    assert result["max_risk"]["level"] == "CRITICAL"


def test_helper_uses_default_database_and_report_dir(scan, helper):
    _, scan_id = scan
    result = helper.call("reports.generate", {"scan_id": scan_id, "formats": ["json"]}, timeout=60)
    assert Path(result["files"][0]["path"]).parent.name == "reports"


@pytest.mark.parametrize("params, field", [
    ({"scan_id": "1"}, "scan_id"),
    ({"scan_id": 1, "formats": "pdf"}, "formats"),
    ({"scan_id": 1, "formats": ["exe"]}, "formats"),
    ({"scan_id": 1, "output_dir": "relativo"}, "output_dir"),
    ({"scan_id": 1, "include_clean": "yes"}, "include_clean"),
])
def test_helper_validates_parameters(helper, params, field):
    with pytest.raises(HelperError) as exc:
        helper.call("reports.generate", params)
    assert exc.value.reason == "invalid_params" and exc.value.code == -32602 and exc.value.details.get("field") == field


def test_helper_rejects_unknown_parameters(helper):
    with pytest.raises(HelperError) as exc:
        helper.call("reports.generate", {"scan_id": 1, "shell_command": "calc"})
    assert exc.value.reason == "invalid_params"


def test_helper_not_found(helper, db):
    with pytest.raises(HelperError) as exc:
        helper.call("reports.generate", {"scan_id": 4242, "formats": ["json"]})
    assert exc.value.reason == "not_found" and exc.value.code == 1001


def test_helper_lists_formats(helper):
    info = helper.call("reports.formats")
    assert info["formats"] == ["json", "html", "pdf"]
    assert "reports.generate" in helper.call("system.info")["methods"]
