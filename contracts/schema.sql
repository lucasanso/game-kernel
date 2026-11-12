-- Game Kernel SQLite schema — single source of truth for the C++ core and the Python tools.
-- schema_version = 1  (stored in meta.schema_version)
-- Changing this file requires a contract change entry in docs/WORK_SPLIT.md §7 and CHANGELOG.md.
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
