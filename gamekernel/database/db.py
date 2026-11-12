"""Local SQLite storage (WAL) for scans, results, caches, reputation, quarantine and audit log.

Threading model: one connection per thread (thread-local). Writes go through ``tx()``
(BEGIN IMMEDIATE) guarded by a process-wide lock. Worker *processes* never touch the
database; only the scanner orchestrator thread and the UI thread do.

Recovery: on open, ``PRAGMA quick_check`` runs. A corrupt database is moved aside
(``gamekernel.db.corrupt-<timestamp>``) and a fresh one is created; ``recovered_from``
then holds the backup path so the UI can tell the user.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

from .. import app_paths
from ..core.models import (
    AnalysisStatus,
    Classification,
    CrackStatus,
    FileResult,
    RiskLevel,
)

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS scans(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    finished_at REAL,
    mode TEXT NOT NULL,
    origin TEXT NOT NULL DEFAULT 'manual',
    label TEXT,
    targets TEXT NOT NULL,
    status TEXT NOT NULL,
    options TEXT,
    engine_fingerprint TEXT,
    files_found INTEGER NOT NULL DEFAULT 0,
    files_analyzed INTEGER NOT NULL DEFAULT 0,
    files_skipped INTEGER NOT NULL DEFAULT 0,
    files_errors INTEGER NOT NULL DEFAULT 0,
    members_analyzed INTEGER NOT NULL DEFAULT 0,
    threats INTEGER NOT NULL DEFAULT 0,
    suspicious INTEGER NOT NULL DEFAULT 0,
    pua INTEGER NOT NULL DEFAULT 0,
    bytes_scanned INTEGER NOT NULL DEFAULT 0,
    max_risk INTEGER NOT NULL DEFAULT 0,
    summary TEXT,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);

CREATE TABLE IF NOT EXISTS scan_files(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    container TEXT,
    sha256 TEXT,
    size INTEGER NOT NULL DEFAULT 0,
    file_type TEXT,
    status TEXT NOT NULL,
    risk INTEGER NOT NULL DEFAULT 0,
    classification TEXT NOT NULL,
    crack_status TEXT NOT NULL DEFAULT 'none',
    primary_category TEXT,
    possible_fp INTEGER NOT NULL DEFAULT 0,
    analyzed_at REAL,
    result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_files_scan ON scan_files(scan_id, risk DESC);
CREATE INDEX IF NOT EXISTS idx_scan_files_sha ON scan_files(sha256);

CREATE TABLE IF NOT EXISTS path_cache(
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    md5 TEXT,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS verdict_cache(
    sha256 TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    payload TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY(sha256, fingerprint)
);

CREATE TABLE IF NOT EXISTS reputation(
    sha256 TEXT PRIMARY KEY,
    verdict TEXT NOT NULL CHECK(verdict IN ('good','bad')),
    name TEXT,
    source TEXT,
    note TEXT,
    added_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine(
    id TEXT PRIMARY KEY,
    original_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    quarantined_at REAL NOT NULL,
    reason TEXT,
    risk INTEGER NOT NULL DEFAULT 0,
    classification TEXT,
    detection TEXT,
    scan_id INTEGER,
    stored_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('quarantined','restored','deleted')),
    meta_json TEXT
);

CREATE TABLE IF NOT EXISTS quarantine_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id TEXT NOT NULL,
    action TEXT NOT NULL,
    at REAL NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signature_state(
    component TEXT PRIMARY KEY,
    version TEXT,
    installed_at REAL,
    source TEXT,
    details TEXT
);

CREATE TABLE IF NOT EXISTS realtime_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    path TEXT NOT NULL,
    event TEXT NOT NULL,
    sha256 TEXT,
    risk INTEGER NOT NULL DEFAULT 0,
    classification TEXT,
    scan_id INTEGER,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_realtime_at ON realtime_events(at DESC);
"""

GENESIS_HASH = "0" * 64
_SCAN_COLUMNS = {
    "finished_at", "status", "options", "engine_fingerprint", "files_found", "files_analyzed", "files_skipped",
    "files_errors", "members_analyzed", "threats", "suspicious", "pua", "bytes_scanned", "max_risk", "summary",
    "error", "label",
}


def _needs_full_json(r: FileResult) -> bool:
    return bool(
        r.evidences
        or r.status != AnalysisStatus.COMPLETE
        or r.classification not in (Classification.UNKNOWN, Classification.KNOWN_LEGIT)
        or r.crack_status != CrackStatus.NONE
        or r.status_reasons
    )


def _row_to_result(row: sqlite3.Row) -> FileResult:
    if row["result_json"]:
        result = FileResult.from_dict(json.loads(row["result_json"]))
    else:
        path = row["path"]
        name = path.replace("\\", "/").rsplit("::", 1)[-1].rsplit("/", 1)[-1]
        directory = os.path.dirname(path) if "::" not in path else row["container"] or ""
        result = FileResult(
            path=path,
            name=name,
            directory=directory,
            extension=os.path.splitext(name)[1].lower(),
            size=row["size"],
            sha256=row["sha256"],
            file_type=row["file_type"] or "unknown",
            container=row["container"],
            status=AnalysisStatus(row["status"]),
            risk=RiskLevel(row["risk"]),
            classification=Classification(row["classification"]),
            crack_status=CrackStatus(row["crack_status"]),
            analyzed_at=row["analyzed_at"] or 0.0,
        )
    result.__dict__["db_id"] = row["id"]  # convenience for UI actions (quarantine, sandbox reassess)
    return result


class Database:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else app_paths.db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self.recovered_from: str | None = None
        self._open_and_check()

    # ------------------------------------------------------------------ connection
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
        except sqlite3.DatabaseError:
            # A corrupt file fails here; close the handle or Windows refuses to move the file aside.
            conn.close()
            raise
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def _open_and_check(self) -> None:
        try:
            conn = self._connect()
            try:
                status = conn.execute("PRAGMA quick_check").fetchone()[0]
                if status != "ok":
                    raise sqlite3.DatabaseError(f"quick_check: {status}")
                self._migrate(conn)
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            log.error("Database corrupt (%s); recreating", exc)
            self._recover()

    def _recover(self) -> None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
        for suffix in ("", "-wal", "-shm"):
            src = Path(str(self.path) + suffix)
            if src.exists():
                try:
                    os.replace(src, Path(str(backup) + suffix))
                except OSError:
                    src.unlink(missing_ok=True)
        self.recovered_from = str(backup)
        conn = self._connect()
        try:
            self._migrate(conn)
        finally:
            conn.close()

    def _migrate(self, conn: sqlite3.Connection) -> None:
        conn.executescript(SCHEMA)
        row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            conn.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
        elif int(row[0]) > SCHEMA_VERSION:
            raise RuntimeError("Banco de dados criado por uma versão mais nova do Game Kernel")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._write_lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def integrity_check(self) -> str:
        return self.conn.execute("PRAGMA integrity_check").fetchone()[0]

    # ------------------------------------------------------------------ scans
    def create_scan(self, mode: str, targets: list[str], options: dict, fingerprint: str = "",
                    origin: str = "manual", label: str = "") -> int:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO scans(started_at, mode, origin, label, targets, status, options, engine_fingerprint)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (time.time(), mode, origin, label, json.dumps(targets, ensure_ascii=False), "running",
                 json.dumps(options, ensure_ascii=False), fingerprint),
            )
            return int(cur.lastrowid)

    def update_scan(self, scan_id: int, **fields: Any) -> None:
        unknown = set(fields) - _SCAN_COLUMNS
        if unknown:
            raise KeyError(f"colunas desconhecidas: {unknown}")
        if not fields:
            return
        values = []
        for key, value in fields.items():
            if key in ("options", "summary") and not isinstance(value, (str, type(None))):
                value = json.dumps(value, ensure_ascii=False)
            if isinstance(value, RiskLevel):
                value = int(value)
            values.append(value)
        assignments = ", ".join(f"{k}=?" for k in fields)
        with self.tx() as c:
            c.execute(f"UPDATE scans SET {assignments} WHERE id=?", (*values, scan_id))

    def finish_scan(self, scan_id: int, status: str, summary: dict | None = None, error: str | None = None) -> None:
        self.update_scan(scan_id, status=status, finished_at=time.time(), summary=summary, error=error)

    def _scan_row(self, row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        d = dict(row)
        d["targets"] = json.loads(d["targets"] or "[]")
        d["options"] = json.loads(d["options"]) if d.get("options") else {}
        d["summary"] = json.loads(d["summary"]) if d.get("summary") else {}
        d["max_risk"] = RiskLevel(d["max_risk"] or 0)
        return d

    def get_scan(self, scan_id: int) -> dict | None:
        return self._scan_row(self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())

    def list_scans(self, limit: int = 100, offset: int = 0, origin: str | None = None) -> list[dict]:
        sql = "SELECT * FROM scans"
        args: list[Any] = []
        if origin:
            sql += " WHERE origin=?"
            args.append(origin)
        sql += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
        args += [limit, offset]
        return [self._scan_row(r) for r in self.conn.execute(sql, args).fetchall()]

    def delete_scan(self, scan_id: int) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM scans WHERE id=?", (scan_id,))

    def mark_interrupted_scans(self) -> list[int]:
        """Call once at application start: scans left 'running'/'paused' were interrupted (crash/power loss)."""
        with self.tx() as c:
            ids = [r[0] for r in c.execute("SELECT id FROM scans WHERE status IN ('running','paused')").fetchall()]
            if ids:
                c.execute(
                    f"UPDATE scans SET status='interrupted', finished_at=? WHERE id IN ({','.join('?' * len(ids))})",
                    (time.time(), *ids),
                )
            return ids

    def interrupted_scans(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM scans WHERE status='interrupted' ORDER BY started_at DESC").fetchall()
        return [self._scan_row(r) for r in rows]

    # ------------------------------------------------------------------ file results
    def add_file_results(self, scan_id: int, results: Iterable[FileResult]) -> list[int]:
        ids: list[int] = []
        with self.tx() as c:
            for r in results:
                cur = c.execute(
                    "INSERT INTO scan_files(scan_id, path, container, sha256, size, file_type, status, risk,"
                    " classification, crack_status, primary_category, possible_fp, analyzed_at, result_json)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        scan_id, r.path, r.container, r.sha256, r.size, r.file_type, r.status.value, int(r.risk),
                        r.classification.value, r.crack_status.value,
                        r.primary_category.value if r.primary_category else None,
                        int(r.possible_false_positive), r.analyzed_at or time.time(),
                        json.dumps(r.to_dict(), ensure_ascii=False) if _needs_full_json(r) else None,
                    ),
                )
                ids.append(int(cur.lastrowid))
        return ids

    def update_file_result(self, row_id: int, r: FileResult) -> None:
        """Replace a stored result (used after sandbox re-assessment or user reputation changes)."""
        with self.tx() as c:
            c.execute(
                "UPDATE scan_files SET sha256=?, status=?, risk=?, classification=?, crack_status=?,"
                " primary_category=?, possible_fp=?, analyzed_at=?, result_json=? WHERE id=?",
                (
                    r.sha256, r.status.value, int(r.risk), r.classification.value, r.crack_status.value,
                    r.primary_category.value if r.primary_category else None, int(r.possible_false_positive),
                    r.analyzed_at or time.time(), json.dumps(r.to_dict(), ensure_ascii=False), row_id,
                ),
            )

    @staticmethod
    def _filters(scan_id: int, min_risk: RiskLevel | None, classifications: list[str] | None,
                 statuses: list[str] | None, only_possible_fp: bool, search: str | None,
                 crack_only: bool) -> tuple[str, list[Any]]:
        where = ["scan_id=?"]
        args: list[Any] = [scan_id]
        if min_risk is not None:
            where.append("risk>=?")
            args.append(int(min_risk))
        if classifications:
            where.append(f"classification IN ({','.join('?' * len(classifications))})")
            args += list(classifications)
        if statuses:
            where.append(f"status IN ({','.join('?' * len(statuses))})")
            args += list(statuses)
        if only_possible_fp:
            where.append("possible_fp=1")
        if crack_only:
            where.append("crack_status<>'none'")
        if search:
            where.append("(path LIKE ? ESCAPE '\\' OR sha256 LIKE ?)")
            pattern = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            args += [pattern, search.lower() + "%"]
        return " AND ".join(where), args

    def get_file_results(self, scan_id: int, *, min_risk: RiskLevel | None = None,
                         classifications: list[str] | None = None, statuses: list[str] | None = None,
                         only_possible_fp: bool = False, search: str | None = None, crack_only: bool = False,
                         limit: int = 500, offset: int = 0) -> list[FileResult]:
        where, args = self._filters(scan_id, min_risk, classifications, statuses, only_possible_fp, search, crack_only)
        rows = self.conn.execute(
            f"SELECT * FROM scan_files WHERE {where} ORDER BY risk DESC, path LIMIT ? OFFSET ?",
            (*args, limit, offset),
        ).fetchall()
        return [_row_to_result(r) for r in rows]

    def count_file_results(self, scan_id: int, *, min_risk: RiskLevel | None = None,
                           classifications: list[str] | None = None, statuses: list[str] | None = None,
                           only_possible_fp: bool = False, search: str | None = None,
                           crack_only: bool = False) -> int:
        where, args = self._filters(scan_id, min_risk, classifications, statuses, only_possible_fp, search, crack_only)
        return int(self.conn.execute(f"SELECT COUNT(*) FROM scan_files WHERE {where}", args).fetchone()[0])

    def get_file_result(self, row_id: int) -> FileResult | None:
        row = self.conn.execute("SELECT * FROM scan_files WHERE id=?", (row_id,)).fetchone()
        return _row_to_result(row) if row else None

    def counts_by_classification(self, scan_id: int) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT classification, COUNT(*) FROM scan_files WHERE scan_id=? GROUP BY classification", (scan_id,)
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    def counts_by_risk(self, scan_id: int) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT risk, COUNT(*) FROM scan_files WHERE scan_id=? GROUP BY risk", (scan_id,)
        ).fetchall()
        return {RiskLevel(r[0]).name: r[1] for r in rows}

    def counts_by_status(self, scan_id: int) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) FROM scan_files WHERE scan_id=? GROUP BY status", (scan_id,)
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    # ------------------------------------------------------------------ caches
    def get_path_cache(self, path: str) -> tuple[int, int, str, str | None] | None:
        row = self.conn.execute("SELECT size, mtime_ns, sha256, md5 FROM path_cache WHERE path=?", (path,)).fetchone()
        return (row[0], row[1], row[2], row[3]) if row else None

    def put_path_cache(self, entries: Iterable[tuple[str, int, int, str, str | None]]) -> None:
        now = time.time()
        with self.tx() as c:
            c.executemany(
                "INSERT OR REPLACE INTO path_cache(path, size, mtime_ns, sha256, md5, updated_at) VALUES(?,?,?,?,?,?)",
                [(p, s, m, h, md5, now) for p, s, m, h, md5 in entries],
            )

    def get_verdict(self, sha256: str, fingerprint: str) -> dict | None:
        row = self.conn.execute(
            "SELECT payload FROM verdict_cache WHERE sha256=? AND fingerprint=?", (sha256, fingerprint)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def put_verdicts(self, entries: Iterable[tuple[str, str, dict]]) -> None:
        now = time.time()
        with self.tx() as c:
            c.executemany(
                "INSERT OR REPLACE INTO verdict_cache(sha256, fingerprint, payload, updated_at) VALUES(?,?,?,?)",
                [(h, fp, json.dumps(payload, ensure_ascii=False), now) for h, fp, payload in entries],
            )

    def prune_caches(self, current_fingerprint: str, max_age_days: int = 30) -> None:
        cutoff = time.time() - max_age_days * 86400
        with self.tx() as c:
            c.execute("DELETE FROM verdict_cache WHERE fingerprint<>? AND updated_at<?", (current_fingerprint, cutoff))
            c.execute("DELETE FROM path_cache WHERE updated_at<?", (cutoff,))

    def clear_caches(self) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM verdict_cache")
            c.execute("DELETE FROM path_cache")

    # ------------------------------------------------------------------ local reputation
    def set_reputation(self, sha256: str, verdict: str, name: str = "", source: str = "user", note: str = "") -> None:
        if verdict not in ("good", "bad"):
            raise ValueError(verdict)
        with self.tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO reputation(sha256, verdict, name, source, note, added_at) VALUES(?,?,?,?,?,?)",
                (sha256.lower(), verdict, name, source, note, time.time()),
            )

    def get_reputation(self, sha256: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM reputation WHERE sha256=?", (sha256.lower(),)).fetchone()
        return dict(row) if row else None

    def list_reputation(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM reputation ORDER BY added_at DESC").fetchall()]

    def remove_reputation(self, sha256: str) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM reputation WHERE sha256=?", (sha256.lower(),))

    # ------------------------------------------------------------------ quarantine
    def add_quarantine_item(self, item: dict) -> None:
        cols = ("id", "original_path", "sha256", "size", "quarantined_at", "reason", "risk", "classification",
                "detection", "scan_id", "stored_name", "status", "meta_json")
        defaults = {"risk": 0, "size": 0, "status": "quarantined", "quarantined_at": time.time()}
        values = [item.get(k, defaults.get(k)) if item.get(k) is not None else defaults.get(k) for k in cols]
        if isinstance(values[cols.index("meta_json")], dict):
            values[cols.index("meta_json")] = json.dumps(values[cols.index("meta_json")], ensure_ascii=False)
        with self.tx() as c:
            c.execute(f"INSERT INTO quarantine({','.join(cols)}) VALUES({','.join('?' * len(cols))})", values)

    def update_quarantine_status(self, item_id: str, status: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE quarantine SET status=? WHERE id=?", (status, item_id))

    def get_quarantine_item(self, item_id: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM quarantine WHERE id=?", (item_id,)).fetchone()
        return self._q_row(row)

    def list_quarantine(self, status: str | None = "quarantined") -> list[dict]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM quarantine WHERE status=? ORDER BY quarantined_at DESC", (status,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM quarantine ORDER BY quarantined_at DESC").fetchall()
        return [self._q_row(r) for r in rows]

    @staticmethod
    def _q_row(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        d = dict(row)
        d["meta"] = json.loads(d.pop("meta_json") or "{}")
        return d

    def add_quarantine_event(self, item_id: str, action: str, detail: str = "") -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO quarantine_events(item_id, action, at, detail) VALUES(?,?,?,?)",
                (item_id, action, time.time(), detail),
            )

    def list_quarantine_events(self, item_id: str | None = None, limit: int = 1000) -> list[dict]:
        if item_id:
            rows = self.conn.execute(
                "SELECT * FROM quarantine_events WHERE item_id=? ORDER BY at DESC LIMIT ?", (item_id, limit)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM quarantine_events ORDER BY at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ audit log (hash chained)
    @staticmethod
    def _audit_hash(prev_hash: str, at: float, actor: str, action: str, detail: str) -> str:
        payload = json.dumps([prev_hash, round(at, 6), actor, action, detail], ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def append_audit(self, action: str, detail: str = "", actor: str = "user") -> None:
        with self.tx() as c:
            row = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS_HASH
            at = round(time.time(), 6)
            c.execute(
                "INSERT INTO audit_log(at, actor, action, detail, prev_hash, hash) VALUES(?,?,?,?,?,?)",
                (at, actor, action, detail, prev, self._audit_hash(prev, at, actor, action, detail)),
            )

    def list_audit(self, limit: int = 500) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    def verify_audit_chain(self) -> tuple[bool, int | None]:
        """Return (ok, id_of_first_broken_entry)."""
        prev = GENESIS_HASH
        for row in self.conn.execute("SELECT * FROM audit_log ORDER BY id"):
            expected = self._audit_hash(prev, row["at"], row["actor"], row["action"], row["detail"] or "")
            if row["prev_hash"] != prev or row["hash"] != expected:
                return False, int(row["id"])
            prev = row["hash"]
        return True, None

    # ------------------------------------------------------------------ signature state
    def set_signature_state(self, component: str, version: str, source: str, details: dict | None = None) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO signature_state(component, version, installed_at, source, details)"
                " VALUES(?,?,?,?,?)",
                (component, version, time.time(), source, json.dumps(details or {}, ensure_ascii=False)),
            )

    def get_signature_states(self) -> dict[str, dict]:
        out = {}
        for row in self.conn.execute("SELECT * FROM signature_state"):
            d = dict(row)
            d["details"] = json.loads(d["details"] or "{}")
            out[d["component"]] = d
        return out

    # ------------------------------------------------------------------ realtime events
    def add_realtime_event(self, path: str, event: str, sha256: str | None = None, risk: RiskLevel = RiskLevel.NONE,
                           classification: str | None = None, scan_id: int | None = None, detail: str = "") -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO realtime_events(at, path, event, sha256, risk, classification, scan_id, detail)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (time.time(), path, event, sha256, int(risk), classification, scan_id, detail),
            )

    def list_realtime_events(self, limit: int = 500) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM realtime_events ORDER BY at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ dashboard
    def dashboard_stats(self) -> dict:
        c = self.conn
        totals = c.execute(
            "SELECT COALESCE(SUM(files_analyzed),0), COALESCE(SUM(threats),0), COALESCE(SUM(suspicious),0),"
            " COALESCE(SUM(pua),0), COUNT(*) FROM scans WHERE status IN ('completed','cancelled','interrupted')"
        ).fetchone()
        last = c.execute(
            "SELECT * FROM scans WHERE status<>'running' ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        quarantined = c.execute("SELECT COUNT(*) FROM quarantine WHERE status='quarantined'").fetchone()[0]
        return {
            "files_analyzed": totals[0],
            "threats": totals[1],
            "suspicious": totals[2],
            "pua": totals[3],
            "scans": totals[4],
            "quarantined": quarantined,
            "last_scan": self._scan_row(last),
        }
