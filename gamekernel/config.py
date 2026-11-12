"""Persistent settings (JSON in the data directory) with defaults and validation."""

from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path
from typing import Any

from . import app_paths


def _default_workers() -> int:
    cpus = os.cpu_count() or 2
    return max(1, min(6, cpus - 1))


DEFAULTS: dict[str, Any] = {
    "version": 1,
    "scan": {
        "default_mode": "deep",            # "quick" | "deep"
        "max_workers": _default_workers(),
        "max_cpu_percent": 75,              # throttle target for the worker pool
        "low_priority": True,               # run workers below normal priority
        "max_file_size_mb": 512,            # bigger files: header sniff + hash + ClamAV only
        "max_archive_depth": 4,
        "max_archive_total_mb": 2048,       # total uncompressed bytes per top-level archive
        "max_archive_members": 20000,
        "max_compression_ratio": 250,       # per member; above => decompression bomb
        "max_member_size_mb": 256,
        "excluded_paths": [],
        "excluded_extensions": [],
        "follow_symlinks": False,
        "file_types": {
            "executables": True,
            "libraries": True,
            "drivers": True,
            "scripts": True,
            "archives": True,
            "installers": True,
            "java": True,
            "shortcuts": True,
            "data_sniffing": True,          # header check of every other file (disguised PE)
        },
    },
    "engines": {
        "clamav": {"enabled": True, "detect_pua": True, "heuristic_alerts": True, "batch_size": 400},
        "yara": {"enabled": True},
        "pe": {"enabled": True},
        "authenticode": {"enabled": True},
        "strings": {"enabled": True, "max_scan_mb": 64},
        "scripts": {"enabled": True},
        "archives": {"enabled": True},
        "pyinstaller": {"enabled": True},
        "game_context": {"enabled": True},
        "reputation": {"enabled": True},
    },
    "quarantine": {"max_size_gb": 20},
    "realtime": {
        "enabled": False,
        "folders": [],
        "notify_min_risk": "MEDIUM",
        "auto_quarantine": False,           # only signature/IOC confirmed malware, opt-in
        "batch_seconds": 8,
        "stable_seconds": 2,
        "max_workers": 1,
    },
    "updates": {"stale_after_days": 7},
    "reports": {"redact_username": True, "include_hostname": False},
    "sandbox": {"enabled": False, "timeout_seconds": 120, "sysmon_path": ""},
    "ui": {"minimize_to_tray": True, "animations": True},
    "logging": {"level": "INFO"},
}

RISK_NAMES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _merge(out[key], value)
        elif key in out:
            out[key] = value
    return out


def _clamp(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        return max(lo, min(hi, int(value)))
    except (TypeError, ValueError):
        return default


def validate(cfg: dict) -> dict:
    """Coerce values into safe ranges. Unknown keys are dropped by _merge."""
    s = cfg["scan"]
    d = DEFAULTS["scan"]
    s["default_mode"] = s["default_mode"] if s["default_mode"] in ("quick", "deep") else "deep"
    s["max_workers"] = _clamp(s["max_workers"], 1, 32, d["max_workers"])
    s["max_cpu_percent"] = _clamp(s["max_cpu_percent"], 10, 100, d["max_cpu_percent"])
    s["max_file_size_mb"] = _clamp(s["max_file_size_mb"], 8, 16384, d["max_file_size_mb"])
    s["max_archive_depth"] = _clamp(s["max_archive_depth"], 0, 10, d["max_archive_depth"])
    s["max_archive_total_mb"] = _clamp(s["max_archive_total_mb"], 16, 65536, d["max_archive_total_mb"])
    s["max_archive_members"] = _clamp(s["max_archive_members"], 10, 1_000_000, d["max_archive_members"])
    s["max_compression_ratio"] = _clamp(s["max_compression_ratio"], 10, 10_000, d["max_compression_ratio"])
    s["max_member_size_mb"] = _clamp(s["max_member_size_mb"], 1, 4096, d["max_member_size_mb"])
    s["excluded_paths"] = [str(p) for p in s.get("excluded_paths") or [] if str(p).strip()]
    s["excluded_extensions"] = sorted(
        {("." + str(e).lower().lstrip(".")) for e in s.get("excluded_extensions") or [] if str(e).strip()}
    )
    r = cfg["realtime"]
    r["folders"] = [str(p) for p in r.get("folders") or [] if str(p).strip()]
    r["notify_min_risk"] = r["notify_min_risk"] if r["notify_min_risk"] in RISK_NAMES else "MEDIUM"
    r["batch_seconds"] = _clamp(r["batch_seconds"], 2, 300, 8)
    r["stable_seconds"] = _clamp(r["stable_seconds"], 1, 60, 2)
    r["max_workers"] = _clamp(r["max_workers"], 1, 8, 1)
    cfg["updates"]["stale_after_days"] = _clamp(cfg["updates"]["stale_after_days"], 1, 365, 7)
    cfg["sandbox"]["timeout_seconds"] = _clamp(cfg["sandbox"]["timeout_seconds"], 30, 1800, 120)
    cfg["quarantine"]["max_size_gb"] = _clamp(cfg["quarantine"]["max_size_gb"], 1, 1024, 20)
    cfg["engines"]["clamav"]["batch_size"] = _clamp(cfg["engines"]["clamav"]["batch_size"], 10, 5000, 400)
    cfg["engines"]["strings"]["max_scan_mb"] = _clamp(cfg["engines"]["strings"]["max_scan_mb"], 1, 1024, 64)
    if cfg["logging"]["level"] not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        cfg["logging"]["level"] = "INFO"
    return cfg


class Settings:
    """Thread-safe settings store backed by settings.json (atomic writes)."""

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else app_paths.settings_path()
        self._lock = threading.RLock()
        self._data = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    return validate(_merge(DEFAULTS, raw))
            except (OSError, ValueError):
                # Corrupt file: keep a copy for diagnosis and fall back to defaults.
                try:
                    self.path.replace(self.path.with_suffix(".corrupt.json"))
                except OSError:
                    pass
        return validate(copy.deepcopy(DEFAULTS))

    def save(self) -> None:
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, self.path)

    def get(self, dotted: str, default: Any = None) -> Any:
        with self._lock:
            node: Any = self._data
            for part in dotted.split("."):
                if not isinstance(node, dict) or part not in node:
                    return default
                node = node[part]
            return copy.deepcopy(node)

    def set(self, dotted: str, value: Any) -> None:
        with self._lock:
            parts = dotted.split(".")
            node = self._data
            for part in parts[:-1]:
                node = node[part]
            if parts[-1] not in node:
                raise KeyError(dotted)
            node[parts[-1]] = value
            self._data = validate(self._data)

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._data)

    def replace(self, data: dict) -> None:
        with self._lock:
            self._data = validate(_merge(DEFAULTS, data))

    def reset(self) -> None:
        with self._lock:
            self._data = validate(copy.deepcopy(DEFAULTS))
