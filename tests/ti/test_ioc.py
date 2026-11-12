"""Threat-intelligence indicators: normalisation, de-duplication, conflicts, readers, and the
validator equivalence with the C++ installer (gk-update validate --component ioc)."""

from __future__ import annotations

import json

import pytest

from gamekernel.ti import ioc
from tests.updates.conftest import run_gk_update

H1, H2, H3 = "1" * 64, "2" * 64, "3" * 64


def test_normalize_hash_variants():
    assert ioc.normalize_hash(" " + "AB" * 32 + " ") == "ab" * 32
    assert ioc.normalize_hash("sha256=" + "cd" * 32) == "cd" * 32
    for bad, fragment in (("d41d8cd98f00b204e9800998ecf8427e", "MD5"), ("a" * 40, "SHA-1"),
                          ("xyz", "inválido"), ("a" * 63, "tamanho")):
        with pytest.raises(ioc.IocError, match=fragment):
            ioc.normalize_hash(bad)


def test_normalize_entry_defaults_and_aliases():
    ind = ioc.normalize_entry({"sha256": H1, "verdict": "Malicious", "category": "RAT"}, default_source="feed")
    assert (ind.verdict, ind.category, ind.severity, ind.sources) == ("bad", "rat", "HIGH", ["feed"])
    assert ioc.normalize_entry({"sha256": H2, "verdict": "clean"}).severity == "INFO"
    with pytest.raises(ioc.IocError, match="categoria"):
        ioc.normalize_entry({"sha256": H1, "verdict": "bad", "category": "virus_x"})
    with pytest.raises(ioc.IocError, match="controle"):
        ioc.normalize_entry({"sha256": H1, "verdict": "bad", "name": "a\x07b"})


def test_merge_deduplicates_and_reports_conflicts():
    items = [
        ioc.Indicator(H1, "bad", "A", "trojan", "MEDIUM", ["f1"]),
        ioc.Indicator(H1, "bad", "", "", "CRITICAL", ["f2"]),
        ioc.Indicator(H2, "good", "Jogo", "", "INFO", ["f1"]),
        ioc.Indicator(H3, "bad", "X", "rat", "HIGH", ["f1"]),
        ioc.Indicator(H3, "good", "X", "", "INFO", ["f2"]),
    ]
    merged, rep = ioc.merge(items)
    by_hash = {i.sha256: i for i in merged}
    assert set(by_hash) == {H1, H2}
    assert by_hash[H1].severity == "CRITICAL" and by_hash[H1].sources == ["f1", "f2"] and by_hash[H1].name == "A"
    assert rep.duplicates_merged == 1 and rep.conflicts[0]["sha256"] == H3 and not rep.ok
    merged, rep = ioc.merge(items, prefer_bad_on_conflict=True)
    assert {i.sha256: i.verdict for i in merged}[H3] == "bad" and rep.ok and rep.warnings


def test_readers(tmp_path):
    (tmp_path / "list.txt").write_text(f"# comentário\n{H1}  arquivo.exe\n\n{H2.upper()}\nlixo\n", encoding="utf-8")
    inds, rejected = ioc.read_source(tmp_path / "list.txt", default_verdict="bad", default_category="trojan")
    assert [i.sha256 for i in inds] == [H1, H2] and all(i.category == "trojan" for i in inds)
    assert len(rejected) == 1 and "linha 5" in rejected[0]
    (tmp_path / "feed.csv").write_text(f"sha256;verdict;name\n{H3};bad;Stealer\n{H1};good;ok\n", encoding="utf-8")
    inds, rejected = ioc.read_source(tmp_path / "feed.csv")
    assert [(i.sha256, i.verdict) for i in inds] == [(H3, "bad"), (H1, "good")] and not rejected
    with pytest.raises(ioc.IocError, match="veredito"):
        ioc.read_source(tmp_path / "list.txt")


def test_written_document_is_deterministic_and_valid(tmp_path):
    merged, _ = ioc.merge([ioc.Indicator(H2, "good"), ioc.Indicator(H1, "bad", category="trojan", severity="HIGH")])
    out = tmp_path / "ioc"
    out.mkdir()
    ioc.write_document(merged, "2026.11.12", out / "a.json")
    first = (out / "a.json").read_bytes()
    ioc.write_document(merged, "2026.11.12", out / "a.json")
    assert (out / "a.json").read_bytes() == first
    assert [e["sha256"] for e in json.loads(first)["entries"]] == [H1, H2]
    assert ioc.validate_ioc_dir(out) == (True, [], 2)


CASES = {
    "valid": {"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": H1, "verdict": "bad", "severity": "LOW"}]},
    "uppercase_hash": {"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": H1.upper().replace("1", "A"), "verdict": "bad"}]},
    "bad_verdict": {"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": H1, "verdict": "evil"}]},
    "bad_severity": {"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": H1, "verdict": "bad", "severity": 5}]},
    "bad_category": {"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": H1, "verdict": "bad", "category": "Trojan!"}]},
    "null_name": {"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": H1, "verdict": "bad", "name": None}]},
    "long_note": {"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": H1, "verdict": "bad", "note": "é" * 513}]},
    "note_512": {"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": H1, "verdict": "bad", "note": "é" * 512}]},
    "conflict": {"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": H1, "verdict": "bad"}, {"sha256": H1, "verdict": "good"}]},
    "duplicate_same": {"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": H1, "verdict": "bad"}, {"sha256": H1, "verdict": "bad"}]},
    "no_version": {"format": "gamekernel-ioc", "entries": []},
    "wrong_format": {"format": "other", "version": "1", "entries": []},
    "entries_not_list": {"format": "gamekernel-ioc", "version": "1", "entries": {}},
    "entry_not_object": {"format": "gamekernel-ioc", "version": "1", "entries": [5]},
    "empty_entries": {"format": "gamekernel-ioc", "version": "1", "entries": []},
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_ioc_validator_equivalence_with_cpp(gk_update, tmp_path, case):
    d = tmp_path / case
    d.mkdir()
    (d / "x.json").write_text(json.dumps(CASES[case], ensure_ascii=False), encoding="utf-8")
    ok, _, count = ioc.validate_ioc_dir(d)
    code, out = run_gk_update(gk_update, "validate", "--component", "ioc", "--dir", d)
    assert (out["ok"], out["count"]) == (ok, count), (case, out)
    assert code == (0 if ok else 1)


def test_ioc_validator_cross_file_conflict_and_garbage(gk_update, tmp_path):
    d = tmp_path / "multi"
    d.mkdir()
    (d / "a.json").write_text(json.dumps(CASES["valid"]), encoding="utf-8")
    (d / "b.json").write_text(json.dumps({"format": "gamekernel-ioc", "version": "1",
                                          "entries": [{"sha256": H1, "verdict": "good"}]}), encoding="utf-8")
    assert ioc.validate_ioc_dir(d)[0] is False
    assert run_gk_update(gk_update, "validate", "--component", "ioc", "--dir", d)[1]["ok"] is False
    (d / "b.json").write_text("{not json", encoding="utf-8")
    assert ioc.validate_ioc_dir(d)[0] is False
    assert run_gk_update(gk_update, "validate", "--component", "ioc", "--dir", d)[1]["ok"] is False
