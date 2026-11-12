"""Cross-language integration: the C++ gk-ipc client (cpp/ipc) against the real Python helpers,
including an end-to-end report generated from a scan stored in SQLite."""

from __future__ import annotations

import re
import sys

from gamekernel.database.db import Database

from tests.corpus import sample_scan
from .native_build import ROOT, build_project, run_qtest


def test_cpp_ipc_client_against_python_helpers(isolated_data_dir, tmp_path):
    exe = build_project("native-ipc", ROOT / "cpp" / "ipc", "gk_ipc_tests")
    db = Database()
    scan_id = sample_scan.build(db)
    db.close()
    out = tmp_path / "reports"
    out.mkdir()
    code, report = run_qtest(exe, {"GK_PYTHON": sys.executable, "GK_REPO": str(ROOT),
                                   "GAMEKERNEL_DATA_DIR": str(isolated_data_dir),
                                   "GK_REPORT_DB": str(db.path), "GK_REPORT_SCAN": str(scan_id),
                                   "GK_REPORT_OUT": str(out)})
    totals = re.search(r"Totals: (\d+) passed, (\d+) failed, (\d+) skipped", report)
    assert code == 0 and totals, report
    passed, failed, skipped = map(int, totals.groups())
    assert failed == 0, report
    assert skipped == 0, f"testes C++ pulados inesperadamente:\n{report}"
    assert passed >= 30, report
    assert len(list(out.glob("*.pdf"))) == 1
