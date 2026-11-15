"""Performance Monitor and System Optimizer (cpp/perf, cpp/sysopt — M12) on the real machine.

tst_perf: processor, memory, disk and the busiest processes as measured by the operating system (Windows
counters, DXGI and Toolhelp in the Windows CI; /proc on Linux), with a busy thread that this process must show,
and GPU metrics present or explained. tst_sysopt: the read-only diagnostics (each with a value and, when it
needs attention, what to do), and the two-step clean-up of temporary files on folders built by the test — only
old files listed by the analysis and still unchanged are deleted; recent files, files in use, links and user
data behind a folder swapped for a link are kept. Nothing on the system is changed.
"""

from __future__ import annotations

import re

import pytest

from tests.integration.native_build import build_root_target, run_qtest


@pytest.mark.parametrize("target, minimum", [("gk_perf_tests", 3), ("gk_sysopt_tests", 5)])
def test_performance_monitor_and_optimizer(target, minimum, isolated_data_dir):
    exe = build_root_target(target)
    code, report = run_qtest(exe, {"GAMEKERNEL_DATA_DIR": str(isolated_data_dir)}, timeout=600)
    totals = re.search(r"Totals: (\d+) passed, (\d+) failed, (\d+) skipped", report)
    assert code == 0 and totals, report
    passed, failed, skipped = map(int, totals.groups())
    assert failed == 0 and skipped == 0 and passed >= minimum, report
