"""Real-time protection (cpp/realtime, M11) against real folders and the real core.

The QtTest suite (cpp/realtime/tests/tst_realtime.cpp) checks the batching rules with a simulated clock
(files are scanned only once they stopped changing; removed, renamed-away and excluded paths are dropped;
lost events become a rescan of the folder), the native watcher (ReadDirectoryChangesW on Windows, inotify on
Linux: created, changed, renamed and removed files, new subfolders, a folder that disappears), and the
monitor end to end: an EICAR file written at test time into a watched folder is scanned by isolated
gk-scanworker processes, reported and recorded in realtime_events; with automatic quarantine on it is
isolated, and once the user restores it, it is not isolated again; the program's data folder is never
watched. Nothing is executed.
"""

from __future__ import annotations

import re

from tests.integration.native_build import build_root_target, run_qtest


def test_realtime_protection_against_real_folders(isolated_data_dir):
    exe = build_root_target("gk_realtime_tests")
    code, report = run_qtest(exe, {"GAMEKERNEL_DATA_DIR": str(isolated_data_dir)}, timeout=900)
    totals = re.search(r"Totals: (\d+) passed, (\d+) failed, (\d+) skipped", report)
    assert code == 0 and totals, report
    passed, failed, skipped = map(int, totals.groups())
    assert failed == 0 and skipped == 0 and passed >= 12, report
