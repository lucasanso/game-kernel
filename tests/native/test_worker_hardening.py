"""gk-scanworker hardens itself before reading untrusted input, and still analyses correctly afterwards.

The real worker is driven over gk-ipc v1 (4-byte little-endian length + JSON). On Windows the token must
report Low integrity with every privilege disabled and the mitigation policies applied; Authenticode trust
(WinVerifyTrust and the system catalogs) must still work from inside that token. On Linux: no_new_privs.
Samples are generated at test time; nothing analysed is executed.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IS_WINDOWS = os.name == "nt"
EXE = ".exe" if IS_WINDOWS else ""
CANDIDATES = [ROOT / "build" / p / "cpp" / "worker" / f"gk-scanworker{EXE}"
              for p in ("linux-release", "linux-debug", "linux-asan")] + \
             [ROOT / "build" / "windows-release" / "cpp" / "worker" / "Release" / "gk-scanworker.exe"]


class WorkerProcess:
    def __init__(self, program: Path):
        self.proc = subprocess.Popen(
            [str(program), "--rules", str(ROOT / "signatures" / "yara"),
             "--indicators", str(ROOT / "signatures" / "internal" / "indicators.yar")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.hello = self._read()
        self._next = 1

    def _read(self) -> dict:
        header = self.proc.stdout.read(4)
        assert len(header) == 4, self.proc.stderr.read().decode(errors="replace")
        (n,) = struct.unpack("<I", header)
        return json.loads(self.proc.stdout.read(n))

    def call(self, method: str, params: dict | None = None) -> dict:
        rid = self._next
        self._next += 1
        body = json.dumps({"v": 1, "type": "request", "id": rid, "method": method, "params": params or {}}).encode()
        self.proc.stdin.write(struct.pack("<I", len(body)) + body)
        self.proc.stdin.flush()
        while True:
            msg = self._read()
            if msg.get("id") == rid and ("result" in msg or "error" in msg):
                return msg

    def close(self):
        try:
            self.call("system.shutdown")
        finally:
            self.proc.stdin.close()
            self.proc.wait(timeout=30)


@pytest.fixture
def worker():
    program = next((c for c in CANDIDATES if c.exists()), None)
    if program is None:
        if os.environ.get("GK_REQUIRE_NATIVE") == "1":
            pytest.fail("gk-scanworker não compilado")
        pytest.skip("gk-scanworker não compilado")
    w = WorkerProcess(program)
    yield w
    w.close()


def _analyze(worker, path: Path) -> dict:
    reply = worker.call("analyze", {"path": str(path), "deep": True})
    assert "result" in reply, reply
    return reply["result"]["file"]


def test_hardening_is_applied_and_reported(worker):
    h = worker.hello["hardening"]
    assert h["failures"] == [], h
    if IS_WINDOWS:
        assert h["integrity"] == "low" and h["privileges_disabled"] is True
        assert {"no_child_processes", "no_dynamic_code", "no_extension_points", "image_load_restrictions"} <= set(h["mitigations"])
    else:
        assert "no_new_privs" in h["mitigations"]
        status = Path(f"/proc/{worker.hello['pid']}/status").read_text()
        assert "NoNewPrivs:\t1" in status


def test_analysis_still_works_after_hardening(worker, tmp_path):
    sample = tmp_path / "readme_eicar.com"
    sample.write_bytes(("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*").encode())
    doc = _analyze(worker, sample)
    assert doc["status"] == "complete" and any(e["source"] == "yara" for e in doc["evidences"]), doc["evidences"]


@pytest.mark.skipif(not IS_WINDOWS, reason="WinVerifyTrust só existe no Windows")
def test_signature_trust_works_at_low_integrity(worker, native):
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    doc = _analyze(worker, system32 / "kernel32.dll")
    assert doc["features"]["signature_valid"] is True and "Microsoft" in doc["features"]["signer"], doc["evidences"]
    catalog_only = next(d for d in sorted(system32.glob("*.dll"))
                        if d.stat().st_size < 4 << 20 and d.read_bytes()[:2] == b"MZ"
                        and not native.authenticode_inspect(d.read_bytes())["present"])
    doc = _analyze(worker, catalog_only)
    trusted = [e for e in doc["evidences"] if e["rule_id"] == "PE.Signature.Trusted"]
    assert trusted and trusted[0]["details"]["catalogo"].lower().endswith(".cat"), (catalog_only, doc["evidences"])
