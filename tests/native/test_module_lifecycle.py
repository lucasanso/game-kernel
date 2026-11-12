"""gk_native must load, work and unload cleanly: no crash when the interpreter exits.

Each component runs in its own interpreter so a teardown failure (a native destructor running after Python
finalized, a library's exit handler) shows up as a non-zero exit code naming the component, instead of an
unexplained crash after the whole test session (Windows reports it as 0xC0000005).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

_PRELUDE = """
import sys
sys.path.insert(0, sys.argv[1])
ROOT = sys.argv[2]
import io, zipfile
import gk_native
_buf = io.BytesIO()
with zipfile.ZipFile(_buf, "w") as _zf:
    _zf.writestr("a.txt", "abc")
ZIP = _buf.getvalue()
"""

_COMPONENTS = {
    "import": "pass",
    "errors": """
try:
    gk_native.parse_pe_file(ROOT + "/nao-existe.exe")
except gk_native.GkError as e:
    assert e.args[0] == 1001
else:
    raise SystemExit("GkError esperado")
""",
    "json_results": "assert isinstance(gk_native.parse_pe(b'MZ' + bytes(0x200)), dict)",
    "hash": "assert gk_native.sha256_bytes(b'').startswith('e3b0c442')",
    "yara": """
rules, report = gk_native.YaraRules.compile_source('rule t { strings: $a = "abc" condition: $a }')
assert report["ok"] and rules.scan(b"xxabcxx")
""",
    "archive": "assert gk_native.archive_walk(ZIP, {})['members']",
    "analysis": """
rules = gk_native.AnalysisRules.load([ROOT + "/signatures/yara"], ROOT + "/signatures/internal/indicators.yar")
gk_native.analyze_bytes(ZIP, "a.zip", rules=rules)
""",
    "risk": """
gk_native.risk_assess([], ROOT + "/signatures/data/game_components.json", ROOT + "/contracts/threat_catalog.json")
""",
    "database": """
import tempfile, os
with tempfile.TemporaryDirectory() as d:
    db = gk_native.CoreDatabase.open(os.path.join(d, "gk.db"))
    db.append_audit("test", "lifecycle", "core")
    del db
""",
    "quarantine": """
import tempfile, os
with tempfile.TemporaryDirectory() as d:
    f = os.path.join(d, "a.bin")
    open(f, "wb").write(b"x" * 5000)
    v = gk_native.QuarantineVault.open(os.path.join(d, "vault"))
    p = v.prepare(f)
    meta = p.metadata
    p.commit()
    v.restore(meta["id"], f)
    del p, v
""",
    # The test session loads a second libyara (yara-python, used for equivalence tests) beside gk_native.
    "with_yara_python": """
try:
    import yara
except ImportError:
    raise SystemExit(0)
yara.compile(source='rule u { condition: true }').match(data=b"x")
rules, report = gk_native.YaraRules.compile_source('rule t { condition: true }')
assert rules.scan(b"x")
""",
}


@pytest.mark.parametrize("component", sorted(_COMPONENTS))
def test_interpreter_exits_cleanly(native, component):
    script = _PRELUDE + _COMPONENTS[component]
    native_dir = str(Path(native.__file__).parent)
    result = subprocess.run([sys.executable, "-c", script, native_dir, str(ROOT)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, f"{component}: exit code {result.returncode:#x}\n{result.stderr}"
