"""Shared pytest fixtures (owned by Agent A — add area-specific fixtures in tests/<area>/conftest.py)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Locate the gk_native module (C++ core bindings). Order: $GK_NATIVE_DIR, then the default presets.
_NATIVE_CANDIDATES = [os.environ.get("GK_NATIVE_DIR", "")] + [
    str(ROOT / "build" / preset)
    for preset in ("linux-release/cpp/bindings", "linux-debug/cpp/bindings", "linux-asan/cpp/bindings",
                   "windows-release/cpp/bindings/Release")
]
for _candidate in _NATIVE_CANDIDATES:
    if _candidate and Path(_candidate).is_dir() and any(Path(_candidate).glob("gk_native*")):
        sys.path.insert(0, _candidate)
        break


@pytest.fixture(scope="session")
def native():
    """The C++ core. Skipped when not built, unless GK_REQUIRE_NATIVE=1 (CI) makes it mandatory."""
    try:
        import gk_native
    except ImportError as exc:
        if os.environ.get("GK_REQUIRE_NATIVE") == "1":
            raise
        pytest.skip(f"gk_native não compilado ({exc}); veja docs/BUILD.md")
    return gk_native


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """Every test gets its own data directory (DB, settings, quarantine, signatures)."""
    from gamekernel import app_paths

    data = tmp_path / "gk-data"
    monkeypatch.setenv("GAMEKERNEL_DATA_DIR", str(data))
    app_paths.reset_caches()
    yield data
    app_paths.reset_caches()


@pytest.fixture
def settings(isolated_data_dir):
    from gamekernel.config import Settings

    return Settings()


@pytest.fixture
def db(isolated_data_dir):
    from gamekernel.database.db import Database

    database = Database()
    yield database
    database.close()
