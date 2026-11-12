from gamekernel.core.models import (
    AnalysisStatus, Classification, Confidence, CrackStatus, Evidence, EvidenceSource, FileFeatures,
    FileResult, Location, RiskLevel, ThreatCategory, printable_excerpt,
)
from gamekernel.core.threat_catalog import CATALOG, info


def _evidence():
    return Evidence(
        rule_id="TEST.rule", title="t", source=EvidenceSource.YARA, category=ThreatCategory.KEYLOGGER,
        severity=RiskLevel.HIGH, confidence=Confidence.MEDIUM,
        locations=[Location(kind="string", section=".rdata", offset=0x400, rva=0x2000, excerpt="abc")],
        details={"k": 1}, fp_note="fp", tags=["x"],
    )


def test_evidence_roundtrip():
    ev = _evidence()
    ev.adjusted_severity = RiskLevel.LOW
    back = Evidence.from_dict(ev.to_dict())
    assert back == ev
    assert back.effective_severity == RiskLevel.LOW


def test_file_result_roundtrip():
    r = FileResult(path="C:/g/a.exe", name="a.exe", directory="C:/g", extension=".exe", size=10, sha256="ab",
                   file_type="pe_exe", status=AnalysisStatus.PARTIAL, evidences=[_evidence()],
                   features=FileFeatures(is_pe=True, exports=["x"]), risk=RiskLevel.HIGH,
                   classification=Classification.SUSPICIOUS, crack_status=CrackStatus.SUSPICIOUS,
                   primary_category=ThreatCategory.KEYLOGGER)
    assert FileResult.from_dict(r.to_dict()).to_dict() == r.to_dict()


def test_risk_helpers():
    assert RiskLevel.HIGH.down() == RiskLevel.MEDIUM
    assert RiskLevel.INFO.down() == RiskLevel.INFO
    assert RiskLevel.NONE.down() == RiskLevel.NONE
    assert RiskLevel.parse("critical") == RiskLevel.CRITICAL
    assert all(level.label for level in RiskLevel)


def test_catalog_covers_every_category():
    for category in ThreatCategory:
        assert category in CATALOG, category
        assert info(category).label


def test_printable_excerpt_is_safe():
    out = printable_excerpt(b"ab\x00\x01\ncd" + b"x" * 300, limit=20)
    assert "\x00" not in out and "\n" not in out and out.endswith("…")
