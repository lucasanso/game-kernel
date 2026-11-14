"""C++ SQLite layer (gk::db) and the Python layer share one database: schema, audit chain, recovery.

The C++ side always runs in a *separate process*. Python's sqlite3 module and gk_native carry two different
copies of the SQLite library; two copies inside one process break each other's POSIX locks (closing a
connection of one copy releases the locks of the other and can delete the WAL file — documented by SQLite as
"multiple copies of SQLite in the same application"). In the product this never happens: the application
uses only the C++ library and Python runs in the separate helper process.
"""

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from gamekernel.database.db import Database


def _core(native, db_path: Path, code: str) -> str:
    """Run `code` with `core` = gk_native.CoreDatabase.open(db_path) in a separate process."""
    native_dir = str(Path(native.__file__).parent)
    script = ("import sys; sys.path.insert(0, sys.argv[1]); import gk_native\n"
              "core = gk_native.CoreDatabase.open(sys.argv[2])\n" + code)
    env = dict(os.environ)
    result = subprocess.run([sys.executable, "-c", script, native_dir, str(db_path)], capture_output=True, text=True,
                            env=env, timeout=60)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_audit_chain_is_shared_between_languages(native, tmp_path):
    path = tmp_path / "gk.db"
    _core(native, path, "core.append_audit('quarantine', 'arquivo ç.exe', 'core')")
    py = Database(path)
    py.append_audit("restore", "via Python", "user")
    py.close()
    _core(native, path, "core.append_audit('delete', 'via C++', 'core')")
    py = Database(path)
    assert py.verify_audit_chain() == (True, None)
    assert [e["action"] for e in reversed(py.list_audit())] == ["quarantine", "restore", "delete"]


def test_interrupted_scans_marked_by_core(native, tmp_path):
    path = tmp_path / "gk.db"
    py = Database(path)
    sid = py.create_scan("deep", ["/g"], {})
    py.close()
    assert _core(native, path, "print(core.mark_interrupted_scans())") == "1"
    assert Database(path).get_scan(sid)["status"] == "interrupted"


def test_core_recovers_corrupt_database(native, tmp_path):
    path = tmp_path / "gk.db"
    path.write_bytes(b"not a database" * 200)
    out = _core(native, path, "print(core.recovered_from is not None)")
    assert out == "True"
    sqlite3.connect(path).execute("SELECT 1 FROM scans")
