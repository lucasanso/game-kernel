"""C++ installer (gk::updates::Installer via gk-update): atomic activation, carry-over of
components, downgrade protection, content validation, rollback, crash recovery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gamekernel.updates import package as pkg

from .conftest import YARA_RULE, base_manifest, make_cvd, run_gk_update, write_raw_package


def build(tmp_path, private, version, comps, name=None, **kw) -> Path:
    path = tmp_path / (name or f"pkg-{version}.gkpkg")
    pkg.build_package(path, private, version, comps, publisher="tests", **kw)
    return path


def install(tool, package, root, keys_dir, *extra):
    return run_gk_update(tool, "install", package, "--root", root, "--keys", keys_dir, *extra)


def tree(directory: Path) -> dict[str, bytes]:
    return {str(p.relative_to(directory)): p.read_bytes() for p in sorted(directory.rglob("*")) if p.is_file()}


def test_full_install_layout_and_manifest(gk_update, keypair, components, tmp_path):
    private, keys_dir, _ = keypair
    root = tmp_path / "signatures"
    code, rep = install(gk_update, build(tmp_path, private, "2026.11.12.1", components), root, keys_dir)
    assert code == 0 and rep["ok"], rep
    active = root / "active"
    assert (active / "yara" / "gamekernel_test.yar").read_text(encoding="utf-8") == YARA_RULE
    assert (active / "ioc" / "local.json").exists() and (active / "clamav" / "daily.cvd").exists()
    manifest = json.loads((active / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["format"] == "gamekernel-signatures" and manifest["package_version"] == "2026.11.12.1"
    counts = {c["component"]: c["count"] for c in rep["components"]}
    assert counts == {"yara": 1, "ioc": 2, "clamav": 2 + 5}   # 2 text signatures + 5 declared in the CVD header
    assert manifest["components"]["yara"]["sha256"]["gamekernel_test.yar"]
    assert not any((root / "staging").iterdir())
    history = (root / "install-history.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.loads(history[-1])["action"] == "install"


def test_partial_package_keeps_other_components(gk_update, keypair, components, tmp_path):
    private, keys_dir, _ = keypair
    root = tmp_path / "signatures"
    install(gk_update, build(tmp_path, private, "2026.11.12.1", components), root, keys_dir)
    new_yara = tmp_path / "yara2"
    new_yara.mkdir()
    (new_yara / "v2.yar").write_text(YARA_RULE.replace("GK_Test_Marker", "GK_Test_Marker_V2"), encoding="utf-8")
    code, rep = install(gk_update, build(tmp_path, private, "2026.11.13.1", {"yara": new_yara}), root, keys_dir)
    assert code == 0, rep
    assert sorted(rep["kept_components"]) == ["clamav", "ioc"]
    active = root / "active"
    assert [p.name for p in (active / "yara").iterdir()] == ["v2.yar"]   # replaced, not merged
    assert (active / "ioc" / "local.json").exists() and (active / "clamav" / "daily.cvd").exists()
    manifest = json.loads((active / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["components"]["ioc"]["package_version"] == "2026.11.12.1"
    assert manifest["components"]["yara"]["package_version"] == "2026.11.13.1"
    assert len(manifest["history"]) == 2
    assert (root / "previous" / "yara" / "gamekernel_test.yar").exists()


def test_downgrade_requires_explicit_permission(gk_update, keypair, components, tmp_path):
    private, keys_dir, _ = keypair
    root = tmp_path / "signatures"
    install(gk_update, build(tmp_path, private, "2026.11.12.2", components), root, keys_dir)
    before = tree(root / "active")
    for version in ("2026.11.12.1", "2026.11.12.2"):   # older and equal
        code, rep = install(gk_update, build(tmp_path, private, version, components, name=f"d{version}.gkpkg"),
                            root, keys_dir)
        assert code == 1 and rep["error"]["code"] == "downgrade"
        assert tree(root / "active") == before
    code, rep = install(gk_update, build(tmp_path, private, "2026.11.12.1", components, name="dg.gkpkg"), root,
                        keys_dir, "--allow-downgrade")
    assert code == 0 and rep["active_manifest"]["history"][-1]["downgrade"] is True


@pytest.mark.parametrize("component, content, expected", [
    ("yara", "rule broken { condition: and }", "yara"),
    ("yara", 'include "C:/Windows/win.ini"\nrule x { condition: true }', "include"),
    ("yara", "rule needs_external { condition: unknown_external == 1 }", "yara"),
    ("ioc", json.dumps({"format": "gamekernel-ioc", "version": "1", "entries": [
        {"sha256": "c" * 64, "verdict": "bad"}, {"sha256": "c" * 64, "verdict": "good"}]}), "good"),
    ("ioc", json.dumps({"format": "gamekernel-ioc", "version": "1", "entries": [{"sha256": "C" * 64, "verdict": "bad"}]}),
     "sha256"),
    ("clamav", "linha sem campos suficientes\n", "campos"),
])
def test_invalid_content_is_never_activated(gk_update, keypair, components, tmp_path, component, content, expected):
    private, keys_dir, _ = keypair
    root = tmp_path / "signatures"
    install(gk_update, build(tmp_path, private, "2026.11.12.1", components), root, keys_dir)
    before = tree(root / "active")
    bad = tmp_path / f"bad-{component}"
    bad.mkdir()
    name = {"yara": "bad.yar", "ioc": "bad.json", "clamav": "bad.ndb"}[component]
    payload = content.encode("utf-8")
    manifest = base_manifest(private, {f"{component}/{name}": payload}, version="2026.11.13.1")
    package = write_raw_package(tmp_path / f"bad-{component}.gkpkg", private, manifest, [payload])
    code, rep = install(gk_update, package, root, keys_dir)
    assert code == 1 and rep["error"]["code"] == "validation_failed", rep
    assert any(expected.lower() in d.lower() for d in rep["details"]), rep["details"]
    assert tree(root / "active") == before
    assert not any((root / "staging").iterdir())


def test_cvd_with_wrong_md5_is_rejected(gk_update, keypair, tmp_path):
    private, keys_dir, _ = keypair
    payload = make_cvd(md5="0" * 32)
    manifest = base_manifest(private, {"clamav/daily.cvd": payload})
    code, rep = install(gk_update, write_raw_package(tmp_path / "cvd.gkpkg", private, manifest, [payload]),
                        tmp_path / "sig", keys_dir)
    assert rep["error"]["code"] == "validation_failed" and any("MD5" in d for d in rep["details"])


def test_tampered_package_leaves_everything_untouched(gk_update, keypair, components, tmp_path):
    private, keys_dir, _ = keypair
    root = tmp_path / "signatures"
    install(gk_update, build(tmp_path, private, "2026.11.12.1", components), root, keys_dir)
    before = tree(root / "active")
    good = build(tmp_path, private, "2026.11.13.1", components, name="new.gkpkg")
    data = bytearray(good.read_bytes())
    data[-3] ^= 0xFF
    good.write_bytes(bytes(data))
    code, rep = install(gk_update, good, root, keys_dir)
    assert rep["error"]["code"] == "hash_mismatch"
    assert tree(root / "active") == before and not any((root / "staging").iterdir())


def test_rollback_swaps_active_and_previous(gk_update, keypair, components, tmp_path):
    private, keys_dir, _ = keypair
    root = tmp_path / "signatures"
    code, rep = run_gk_update(gk_update, "rollback", "--root", root)
    assert code == 1 and rep["error"]["code"] == "no_previous"
    install(gk_update, build(tmp_path, private, "2026.11.12.1", components), root, keys_dir)
    install(gk_update, build(tmp_path, private, "2026.11.13.1", {"ioc": components["ioc"]}), root, keys_dir)
    code, rep = run_gk_update(gk_update, "rollback", "--root", root)
    assert code == 0 and rep["package_version"] == "2026.11.12.1" and rep["previous_package_version"] == "2026.11.13.1"
    code, rep = run_gk_update(gk_update, "rollback", "--root", root)   # rollback of the rollback
    assert rep["package_version"] == "2026.11.13.1"
    _, status = run_gk_update(gk_update, "status", "--root", root)
    assert status["active"]["package_version"] == "2026.11.13.1"


def test_recovery_after_crash_between_renames(gk_update, keypair, components, tmp_path):
    private, keys_dir, _ = keypair
    root = tmp_path / "signatures"
    install(gk_update, build(tmp_path, private, "2026.11.12.1", components), root, keys_dir)
    # Simulate a power loss after "active → previous" but before "staging → active".
    (root / "active").rename(root / "previous")
    (root / "staging" / "half-written").mkdir()
    code, rep = install(gk_update, build(tmp_path, private, "2026.11.13.1", components, name="n.gkpkg"), root, keys_dir)
    assert code == 0, rep
    assert any("desfeita" in d for d in rep["details"]) and any("temporários" in d for d in rep["details"])
    assert rep["previous_package_version"] == "2026.11.12.1"


def test_concurrent_install_is_refused(gk_update, keypair, components, tmp_path):
    from PySide6.QtCore import QLockFile

    private, keys_dir, _ = keypair
    root = tmp_path / "signatures"
    (root / "staging").mkdir(parents=True)
    lock = QLockFile(str(root / ".install.lock"))
    assert lock.tryLock(0)
    try:
        code, rep = install(gk_update, build(tmp_path, private, "2026.11.12.1", components), root, keys_dir)
        assert code == 1 and rep["error"]["code"] == "busy"
    finally:
        lock.unlock()


def test_validate_command_matches_python_ioc_validator(gk_update, components, tmp_path):
    from gamekernel.intel import ioc

    code, out = run_gk_update(gk_update, "validate", "--component", "ioc", "--dir", components["ioc"])
    ok, messages, count = ioc.validate_ioc_dir(components["ioc"])
    assert (out["ok"], out["count"]) == (ok, count) == (True, 2)
