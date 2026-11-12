"""End-to-end tests of the helper process: real subprocess, real pipes, real failures."""

from __future__ import annotations

import sys
import time

import pytest

from gamekernel.ipc import protocol as P
from gamekernel.ipc.client import HelperClient, HelperError, sanitized_environment

from .conftest import FAULT_HELPER, ROOT


def test_handshake_and_ping(fault_client):
    assert fault_client.hello["helper"] == "gk-helper"
    assert fault_client.hello["netguard"] is True
    assert "test.sleep" in fault_client.hello["methods"]
    assert fault_client.call("system.ping", {"echo": "olá"}) == {"pong": True, "echo": "olá"}


def test_unknown_method(fault_client):
    with pytest.raises(HelperError) as exc:
        fault_client.call("nope.method")
    assert exc.value.code == P.ErrorCode.UNKNOWN_METHOD


def test_exception_in_service_does_not_kill_helper(fault_client):
    with pytest.raises(HelperError) as exc:
        fault_client.call("test.raise")
    assert exc.value.code == P.ErrorCode.INTERNAL_ERROR
    assert "falha proposital" in exc.value.message
    assert fault_client.call("system.ping")["pong"] is True


def test_structured_service_error(fault_client):
    with pytest.raises(HelperError) as exc:
        fault_client.call("test.service_error")
    assert exc.value.code == P.ErrorCode.INVALID_PARAMS
    assert exc.value.details == {"field": "x"}


def test_stray_stdout_writes_do_not_corrupt_protocol(fault_client):
    assert fault_client.call("test.stdout") == {"ok": True}
    assert fault_client.call("system.ping")["pong"] is True
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not any("lixo no stdout" in line for line in fault_client.stderr_tail):
        time.sleep(0.02)
    assert any("lixo no stdout" in line for line in fault_client.stderr_tail)  # went to stderr


def test_events_are_delivered_before_response(fault_client):
    seen = []
    result = fault_client.call("test.events", {"count": 5}, on_event=lambda name, data: seen.append((name, data)))
    assert result == {"sent": 5}
    assert seen == [("progress", {"i": i}) for i in range(5)]


def test_oversized_result_becomes_resource_limit(fault_client):
    with pytest.raises(HelperError) as exc:
        fault_client.call("test.big")
    assert exc.value.code == P.ErrorCode.RESOURCE_LIMIT
    assert fault_client.call("system.ping")["pong"] is True


def test_non_serialisable_result(fault_client):
    with pytest.raises(HelperError) as exc:
        fault_client.call("test.not_json")
    assert exc.value.code == P.ErrorCode.INTERNAL_ERROR


def test_cooperative_timeout(fault_client):
    with pytest.raises(HelperError) as exc:
        fault_client.call("test.sleep", {"seconds": 30}, timeout=0.5)
    assert exc.value.code == P.ErrorCode.TIMEOUT
    assert fault_client.running
    assert fault_client.call("system.ping")["pong"] is True


def test_hung_service_is_killed_after_grace(fault_client):
    start = time.monotonic()
    with pytest.raises(HelperError) as exc:
        fault_client.call("test.hang", timeout=0.3, grace=0.5)
    assert exc.value.code == P.ErrorCode.TIMEOUT
    assert time.monotonic() - start < 10
    assert not fault_client.running
    # A new helper is started transparently on the next call.
    assert fault_client.call("system.ping")["pong"] is True


def test_hard_crash_is_isolated_and_recoverable(fault_client):
    with pytest.raises(HelperError) as exc:
        fault_client.call("test.crash")
    assert exc.value.code == P.ErrorCode.HELPER_CRASHED
    assert exc.value.retryable
    assert "código de saída 3" in exc.value.message
    assert fault_client.call("system.ping")["pong"] is True


def test_network_is_blocked_inside_helper(fault_client):
    assert fault_client.call("test.network") == {"blocked": True}


def test_helper_exits_when_host_closes_pipe(fault_client):
    fault_client._proc.stdin.close()
    assert fault_client.wait_exit(10) == 0


def test_shutdown_method(fault_client):
    assert fault_client.call("system.shutdown") == {"stopping": True}
    assert fault_client.wait_exit(10) == 0


def test_protocol_violation_closes_helper(fault_client):
    fault_client._proc.stdin.write(b"\x03\x00\x00\x00abc")   # not JSON
    fault_client._proc.stdin.flush()
    assert fault_client.wait_exit(10) == 2


def test_helper_missing_binary_reports_unavailable(isolated_data_dir):
    client = HelperClient([sys.executable, "-I", str(ROOT / "does_not_exist.py")],
                          env=sanitized_environment(isolated_data_dir), cwd=ROOT)
    with pytest.raises(HelperError) as exc:
        client.start()
    assert exc.value.code == P.ErrorCode.HELPER_UNAVAILABLE


def test_real_helper_entry_point(real_client):
    info = real_client.call("system.info")
    assert info["netguard"] is True
    assert info["protocol"] == P.PROTOCOL_VERSION
    assert "system.ping" in info["methods"]


def test_environment_is_sanitised(isolated_data_dir, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/malicious")
    monkeypatch.setenv("SECRET_TOKEN", "x")
    env = sanitized_environment(isolated_data_dir)
    assert "PYTHONPATH" not in env and "SECRET_TOKEN" not in env
    assert env["GAMEKERNEL_DATA_DIR"] == str(isolated_data_dir)


def test_fault_helper_path_exists():
    assert FAULT_HELPER.exists()
