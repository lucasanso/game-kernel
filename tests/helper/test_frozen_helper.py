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
        assert "reports.generate" in info["methods"]
        result = client.call("reports.generate", {"scan_id": scan_id, "formats": ["json", "html", "pdf"],
                                                  "output_dir": str(tmp_path), "db_path": str(db.path)}, timeout=180)
    assert sorted(Path(f["path"]).suffix for f in result["files"]) == [".html", ".json", ".pdf"]
    assert all(Path(f["path"]).stat().st_size == f["size"] for f in result["files"])
