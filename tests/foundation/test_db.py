import sqlite3

from gamekernel.core.models import (
    AnalysisStatus, Classification, Confidence, Evidence, EvidenceSource, FileResult, RiskLevel, ThreatCategory,
)
from gamekernel.database.db import Database


def _result(path, risk=RiskLevel.NONE, cls=Classification.UNKNOWN, evidence=False):
    r = FileResult(path=path, name=path.rsplit("/", 1)[-1], directory="/g", extension=".exe", size=1,
                   sha256="aa" * 32, file_type="pe_exe", risk=risk, classification=cls)
    if evidence:
        r.evidences.append(Evidence("X", "x", EvidenceSource.HEURISTIC, ThreatCategory.LOADER, risk, Confidence.LOW))
    return r


def test_scan_lifecycle_and_queries(db):
    sid = db.create_scan("deep", ["/g"], {"mode": "deep"}, "fp")
    db.add_file_results(sid, [
        _result("/g/clean.exe"),
        _result("/g/bad.exe", RiskLevel.CRITICAL, Classification.MALWARE, evidence=True),
        _result("/g/sus.dll", RiskLevel.MEDIUM, Classification.SUSPICIOUS, evidence=True),
    ])
    db.finish_scan(sid, "completed", {"ok": True})
    assert db.get_scan(sid)["status"] == "completed"
    top = db.get_file_results(sid, min_risk=RiskLevel.MEDIUM)
    assert [r.name for r in top] == ["bad.exe", "sus.dll"]
    assert top[0].evidences and top[0].evidences[0].rule_id == "X"
    clean = db.get_file_results(sid, classifications=["unknown"])
    assert clean[0].name == "clean.exe" and clean[0].status == AnalysisStatus.COMPLETE
    assert db.count_file_results(sid, search="bad") == 1
    assert db.counts_by_classification(sid)["malware"] == 1


def test_interrupted_scans(db):
    sid = db.create_scan("quick", ["/x"], {})
    assert db.mark_interrupted_scans() == [sid]
    assert db.interrupted_scans()[0]["id"] == sid


def test_caches(db):
    db.put_path_cache([("/a", 1, 2, "h", "m")])
    assert db.get_path_cache("/a") == (1, 2, "h", "m")
    db.put_verdicts([("h", "fp", {"e": []})])
    assert db.get_verdict("h", "fp") == {"e": []}
    assert db.get_verdict("h", "other") is None


def test_audit_chain_detects_tampering(db):
    db.append_audit("quarantine", "file a")
    db.append_audit("restore", "file a")
    assert db.verify_audit_chain() == (True, None)
    with db.tx() as c:
        c.execute("UPDATE audit_log SET detail='edited' WHERE id=1")
    ok, bad = db.verify_audit_chain()
    assert not ok and bad == 1


def test_corrupt_database_is_recovered(isolated_data_dir):
    isolated_data_dir.mkdir(parents=True, exist_ok=True)
    path = isolated_data_dir / "broken.db"
    path.write_bytes(b"this is not a sqlite database" * 100)
    database = Database(path)
    assert database.recovered_from is not None
    assert database.list_scans() == []
    sqlite3.connect(path).execute("SELECT 1 FROM scans")


def test_quarantine_and_reputation(db):
    db.add_quarantine_item({"id": "q1", "original_path": "/g/a.exe", "sha256": "aa", "size": 1,
                            "quarantined_at": 1.0, "stored_name": "q1.gkq", "status": "quarantined",
                            "meta_json": {"k": 1}})
    db.add_quarantine_event("q1", "quarantine", "ok")
    assert db.list_quarantine()[0]["meta"] == {"k": 1}
    db.update_quarantine_status("q1", "restored")
    assert db.list_quarantine() == []
    db.set_reputation("AB", "good", "steam_api64.dll")
    assert db.get_reputation("ab")["verdict"] == "good"
    assert db.dashboard_stats()["quarantined"] == 0
