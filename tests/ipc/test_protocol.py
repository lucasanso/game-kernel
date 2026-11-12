"""Unit tests of the gk-ipc v1 framing and envelope validation (no subprocess)."""

from __future__ import annotations

import io
import struct

import pytest

from gamekernel.ipc import protocol as P


def roundtrip(message: dict) -> dict:
    return P.validate_message(P.read_frame(io.BytesIO(P.encode_frame(message))))


def test_roundtrip_all_builders():
    err = P.ServiceError(P.ErrorCode.NOT_FOUND, "não existe", {"scan_id": 3})
    for msg in (
        P.hello("gk-helper", "1.0.0", ["system.ping"], 10, True),
        P.request(1, "reports.generate", {"scan_id": 3}, 5000),
        P.cancel(1),
        P.event(1, "progress", {"done": 2}),
        P.ok_response(1, {"files": []}),
        P.error_response(2, err),
        P.log("INFO", "x", "mensagem com acentuação"),
    ):
        assert roundtrip(msg) == msg


def test_error_response_carries_retryable_flag():
    assert P.error_response(1, P.ServiceError(P.ErrorCode.TIMEOUT, "t"))["error"]["retryable"] is True
    assert P.error_response(1, P.ServiceError(P.ErrorCode.INVALID_PARAMS, "p"))["error"]["retryable"] is False


def test_unknown_error_code_is_rejected():
    with pytest.raises(ValueError):
        P.ServiceError("made_up", "x")


def test_clean_eof_between_frames():
    with pytest.raises(P.ChannelClosed):
        P.read_frame(io.BytesIO(b""))


@pytest.mark.parametrize("data", [
    b"\x05\x00",                                   # truncated header
    struct.pack("<I", 10) + b"{}",                 # truncated payload
    struct.pack("<I", 0),                          # empty frame
    struct.pack("<I", P.DEFAULT_MAX_FRAME + 1),    # oversized frame (rejected before allocation)
    struct.pack("<I", 4) + b"[1] ",                # not an object
    struct.pack("<I", 3) + b"\xff\xfe{",           # invalid UTF-8
    struct.pack("<I", 12) + b'{"a": NaN}  ',       # non-standard JSON constant
])
def test_malformed_frames(data):
    with pytest.raises(P.ProtocolError):
        P.read_frame(io.BytesIO(data))


def test_encode_rejects_oversized_and_nan():
    with pytest.raises(P.ProtocolError):
        P.encode_frame({"x": "y" * 100}, max_frame=50)
    with pytest.raises(ValueError):
        P.encode_frame({"x": float("nan")})


@pytest.mark.parametrize("msg", [
    {"proto": 2, "type": "request", "id": 1, "method": "a.b"},          # other major version
    {"type": "request", "id": 1, "method": "a.b"},                       # no version
    {"proto": 1, "type": "bogus"},
    {"proto": 1, "type": "request", "id": 0, "method": "a.b"},
    {"proto": 1, "type": "request", "id": True, "method": "a.b"},
    {"proto": 1, "type": "request", "id": 2**53, "method": "a.b"},
    {"proto": 1, "type": "request", "id": 1, "method": "nodot"},
    {"proto": 1, "type": "request", "id": 1, "method": "a.b", "params": []},
    {"proto": 1, "type": "request", "id": 1, "method": "a.b", "timeout_ms": -5},
    {"proto": 1, "type": "response", "id": 1, "ok": True},
    {"proto": 1, "type": "response", "id": 1, "ok": False, "error": {"code": "x"}},
    {"proto": 1, "type": "response", "id": 1, "ok": "yes", "result": 1},
    {"proto": 1, "type": "log", "level": "TRACE", "message": "x"},
    {"proto": 1, "type": "event", "id": 1, "name": 5},
])
def test_invalid_envelopes(msg):
    with pytest.raises(P.ProtocolError):
        P.validate_message(msg)


def test_unknown_fields_are_ignored_for_forward_compatibility():
    msg = P.request(7, "system.ping", {})
    msg["future_field"] = {"anything": 1}
    assert P.validate_message(msg)["id"] == 7
