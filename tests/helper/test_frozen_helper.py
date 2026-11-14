"""Smoke test of the *frozen* helper (PyInstaller output). Runs in CI after the build, with
GK_FROZEN_HELPER pointing to dist/gk-helper/gk-helper(.exe); skipped otherwise."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from gamekernel.database.db import Database
from gamekernel.helper.client import HelperClient, sanitized_environment
from tests.corpus import sample_scan

FROZEN = os.environ.get("GK_FROZEN_HELPER")

pytestmark = pytest.mark.skipif(not FROZEN, reason="GK_FROZEN_HELPER não definido (definido na CI após o PyInstaller)")


def test_frozen_helper_generates_reports(isolated_data_dir, tmp_path):
    exe = Path(FROZEN).resolve()
    db = Database()
    scan_id = sample_scan.build(db)
    db.close()
    with HelperClient([str(exe)], env=sanitized_environment(isolated_data_dir), cwd=exe.parent) as client:
        info = client.call("system.info")
        assert info["frozen"] is True and info["netguard"] is True
        # Every service module of the source tree made it into the frozen build (PyInstaller hidden imports).
        from gamekernel.helper.services import registry
        assert info["unavailable_services"] == {}
        assert {svc.method for svc in registry()} <= set(info["methods"]), info["methods"]
        result = client.call("reports.generate", {"scan_id": scan_id, "formats": ["json", "html", "pdf"],
                                                  "output_dir": str(tmp_path), "db_path": str(db.path)}, timeout=180)
    assert sorted(Path(f["path"]).suffix for f in result["files"]) == [".html", ".json", ".pdf"]
    assert all(Path(f["path"]).stat().st_size == f["size"] for f in result["files"])


def test_frozen_helper_ships_the_sandbox_monitor(isolated_data_dir):
    """monitor.ps1 must be inside the frozen bundle (PyInstaller data file), byte for byte."""
    exe = Path(FROZEN).resolve()
    bundled = [p for p in exe.parent.rglob("monitor.ps1") if p.parent.name == "sandbox"]
    source = Path(__file__).resolve().parents[2] / "gamekernel" / "sandbox" / "monitor.ps1"
    assert len(bundled) == 1 and bundled[0].read_bytes() == source.read_bytes()
    with HelperClient([str(exe)], env=sanitized_environment(isolated_data_dir), cwd=exe.parent) as client:
        availability = client.call("sandbox.availability")
    assert "monitor.ps1" not in availability["reason"], availability
