"""contracts/schema.sql must define exactly the schema the Python layer creates (and vice versa)."""

import sqlite3
from pathlib import Path

from gamekernel.database.db import SCHEMA_VERSION, Database

ROOT = Path(__file__).resolve().parents[2]


def _objects(conn):
    rows = conn.execute("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
    return [(t, n, " ".join((s or "").split())) for t, n, s in rows]


def test_schema_sql_matches_python_database(tmp_path):
    from_contract = sqlite3.connect(tmp_path / "contract.db")
    from_contract.executescript((ROOT / "contracts" / "schema.sql").read_text(encoding="utf-8"))
    py_db = Database(tmp_path / "python.db")
    assert _objects(from_contract) == _objects(py_db.conn)
    assert f"schema_version = {SCHEMA_VERSION}" in (ROOT / "contracts" / "schema.sql").read_text(encoding="utf-8")
