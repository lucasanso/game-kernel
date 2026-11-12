"""Cross-language integration: the C++ gk-ipc client (native/ipc) against the real Python helpers."""

from __future__ import annotations

import re
import sys

from .native_build import ROOT, build_project, run_qtest


def test_cpp_ipc_client_against_python_helpers(isolated_data_dir):
    exe = build_project("native-ipc", ROOT / "native" / "ipc", "gk_ipc_tests")
    code, report = run_qtest(exe, {"GK_PYTHON": sys.executable, "GK_REPO": str(ROOT),
                                   "GAMEKERNEL_DATA_DIR": str(isolated_data_dir)})
    totals = re.search(r"Totals: (\d+) passed, (\d+) failed, (\d+) skipped", report)
    assert code == 0 and totals, report
    passed, failed, skipped = map(int, totals.groups())
    assert failed == 0, report
    assert skipped == 0, f"testes C++ pulados inesperadamente:\n{report}"
    assert passed >= 30, report
