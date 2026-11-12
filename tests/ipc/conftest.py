from __future__ import annotations

import sys
from pathlib import Path

import pytest

from gamekernel.ipc.client import HelperClient, sanitized_environment

ROOT = Path(__file__).resolve().parents[2]
FAULT_HELPER = Path(__file__).with_name("fault_helper.py")


@pytest.fixture
def fault_client(isolated_data_dir):
    client = HelperClient([sys.executable, "-I", str(FAULT_HELPER)], env=sanitized_environment(isolated_data_dir),
                          cwd=ROOT)
    client.start()
    yield client
    client.close()


@pytest.fixture
def real_client(isolated_data_dir):
    client = HelperClient([sys.executable, "-I", str(ROOT / "gk_helper.py")],
                          env=sanitized_environment(isolated_data_dir), cwd=ROOT)
    client.start()
    yield client
    client.close()
