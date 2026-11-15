"""Service layer of the desktop application (cpp/bridge, M13) against the real core.

The QtTest suite (cpp/bridge/tests/tst_bridge.cpp) runs real scans with isolated gk-scanworker processes on
samples generated at test time (EICAR assembled at run time), reads the history and results back from
SQLite, pauses and cancels a scan, takes a file through the encrypted quarantine (refusal when the file
changed, list, restore, permanent deletion, verification) and checks a fresh installation and the
installation integrity report.
"""

from __future__ import annotations

import re

from tests.integration.native_build import build_root_target, run_qtest


def test_bridge_services_against_the_real_core(isolated_data_dir):
    exe = build_root_target("gk_bridge_tests")
    code, report = run_qtest(exe, {"GAMEKERNEL_DATA_DIR": str(isolated_data_dir)}, timeout=900)
    totals = re.search(r"Totals: (\d+) passed, (\d+) failed, (\d+) skipped", report)
    assert code == 0 and totals, report
    passed, failed, skipped = map(int, totals.groups())
    assert failed == 0 and skipped == 0 and passed >= 6, report
