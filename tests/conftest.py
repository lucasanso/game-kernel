"""Shared pytest fixtures (owned by Agent A — add area-specific fixtures in tests/<area>/conftest.py)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


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
