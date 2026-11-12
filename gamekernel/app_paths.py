"""Filesystem locations used by Game Kernel (installed, portable and development modes)."""

from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path

from . import APP_ID

IS_WINDOWS = sys.platform == "win32"
IS_FROZEN = bool(getattr(sys, "frozen", False))


@lru_cache(maxsize=1)
def install_dir() -> Path:
    """Directory containing the executable (frozen) or the repository root (development)."""
    if IS_FROZEN:
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


@lru_cache(maxsize=1)
def resource_dir() -> Path:
    """Directory with bundled read-only resources (signatures, keys, assets, tools)."""
    if IS_FROZEN:
        return Path(getattr(sys, "_MEIPASS", install_dir()))
    return install_dir()


def is_portable() -> bool:
    return (install_dir() / "portable.flag").exists()


@lru_cache(maxsize=1)
def data_dir() -> Path:
    override = os.environ.get("GAMEKERNEL_DATA_DIR")
    if override:
        base = Path(override)
    elif is_portable():
        base = install_dir() / "data"
    elif IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_ID
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "game-kernel"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _sub(name: str) -> Path:
    path = data_dir() / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "gamekernel.db"


def settings_path() -> Path:
    return data_dir() / "settings.json"


def quarantine_dir() -> Path:
    return _sub("quarantine")


def reports_dir() -> Path:
    return _sub("reports")


def logs_dir() -> Path:
    return _sub("logs")


def temp_dir() -> Path:
    return _sub("temp")


def sandbox_dir() -> Path:
    return _sub("sandbox")


def installed_signatures_dir() -> Path:
    """Signatures installed from verified offline update packages."""
    return _sub("signatures")


def active_signatures_dir() -> Path:
    """Currently active signatures installed by the offline update manager.

    Layout (contract, see docs/WORK_SPLIT.md §4):
        active/manifest.json   – manifest of the installed package
        active/clamav/         – *.cvd *.cld *.cud *.hdb *.hsb *.ndb *.ldb *.yara ...
        active/yara/           – *.yar / *.yara
        active/ioc/            – *.json (gamekernel-ioc format)
    """
    return installed_signatures_dir() / "active"


def previous_signatures_dir() -> Path:
    """Previous active set, kept for rollback."""
    return installed_signatures_dir() / "previous"


def staging_signatures_dir() -> Path:
    """Temporary location while a package is being verified/installed."""
    return installed_signatures_dir() / "staging"


def builtin_signatures_dir() -> Path:
    return resource_dir() / "signatures"


def trusted_keys_dir() -> Path:
    return resource_dir() / "signatures" / "keys"


def third_party_dir() -> Path:
    return resource_dir() / "third_party"


def asset_path(name: str) -> Path:
    return resource_dir() / "assets" / name


def reset_caches() -> None:
    """Used by tests that change GAMEKERNEL_DATA_DIR."""
    data_dir.cache_clear()
