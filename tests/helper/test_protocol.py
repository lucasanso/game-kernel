"""Unit tests of the helper IPC envelope (docs/INTEGRATION.md §3) and its framing (no subprocess)."""

from __future__ import annotations

import io
import struct

import pytest

from gamekernel.helper import protocol as P


def roundtrip(message: dict) -> dict:
    return P.validate_message(P.read_frame(io.BytesIO(P.encode_frame(message))))


def test_roundtrip_all_builders():
    err = P.ServiceError(P.Reason.NOT_FOUND, "não existe", {"scan_id": 3})
    for msg in (
        P.hello("1.0.0", ["system.ping"], 10, True),
        P.request(1, "reports.generate", {"scan_id": 3}, 5000),
        P.cancel(1),
        P.event("progress", {"done": 2}, 1),
        P.event("progress", {"done": 2}),
        P.ok_response(1, {"files": []}),
        P.ok_response(2, None),
        P.error_response(2, err),
        P.log("INFO", "x", "mensagem com acentuação"),
    ):
        assert roundtrip(msg) == msg


def test_envelope_matches_the_contract():
    assert P.hello("1.0.0", [], 1, True) == {"v": 1, "type": "hello", "component": "gk-helper", "version": "1.0.0",
                                             "protocol": 1, "methods": [], "pid": 1, "netguard": True}
    assert P.request(7, "a.b", {"x": 1}) == {"v": 1, "id": 7, "method": "a.b", "params": {"x": 1}}
    assert P.ok_response(7, {"y": 2}) == {"v": 1, "id": 7, "result": {"y": 2}}
    assert P.log("WARNING", "m", "texto") == {"v": 1, "type": "event", "name": "log",
                                             "data": {"level": "WARNING", "logger": "m", "message": "texto"}}
    assert P.kind_of(P.request(1, "a.b")) == "request" and P.kind_of(P.ok_response(1, 1)) == "response"


@pytest.mark.parametrize("reason, code, retryable", [
    (P.Reason.INVALID_PARAMS, -32602, False), (P.Reason.UNKNOWN_METHOD, -32601, False),
    (P.Reason.NOT_FOUND, 1001, False), (P.Reason.IO_ERROR, 1001, False), (P.Reason.RESOURCE_LIMIT, 1002, False),
    (P.Reason.BUSY, 1002, True), (P.Reason.TIMEOUT, 1003, True), (P.Reason.CANCELLED, 1004, False),
    (P.Reason.INVALID_FORMAT, 1005, False), (P.Reason.INTERNAL_ERROR, 1099, False),
])
def test_error_codes_follow_the_contract(reason, code, retryable):
    error = P.error_response(1, P.ServiceError(reason, "m", {"field": "f"}))["error"]
    assert error == {"code": code, "message": "m", "data": {"field": "f", "reason": reason, "retryable": retryable}}


def test_unknown_reason_is_rejected():
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


def test_limit_is_64_mib_by_default():
    assert P.DEFAULT_MAX_FRAME == 64 * 1024 * 1024


def test_encode_rejects_oversized_and_nan():
    with pytest.raises(P.ProtocolError):
        P.encode_frame({"x": "y" * 100}, max_frame=50)
    with pytest.raises(ValueError):
        P.encode_frame({"x": float("nan")})


@pytest.mark.parametrize("msg", [
    {"id": 1, "method": "a.b"},                                    # no version
    {"v": 2, "id": 1, "method": "a.b"},                            # other version
    {"v": True, "id": 1, "method": "a.b"},
    {"v": 1, "type": "bogus"},
    {"v": 1, "type": "hello", "component": "x"},                   # no protocol
    {"v": 1, "id": 0, "method": "a.b"},
    {"v": 1, "id": True, "method": "a.b"},
    {"v": 1, "id": 2**53, "method": "a.b"},
    {"v": 1, "id": 1, "method": "nodot"},
    {"v": 1, "id": 1, "method": "a.b\n"},
    {"v": 1, "id": 1, "method": "a.b", "params": []},
    {"v": 1, "id": 1, "method": "a.b", "timeout_ms": -5},
    {"v": 1, "id": 1},                                             # neither result nor error
    {"v": 1, "id": 1, "result": 1, "error": {"code": 1, "message": "x"}},
    {"v": 1, "id": 1, "error": {"code": "x", "message": "m"}},     # code must be an integer
    {"v": 1, "id": 1, "error": {"code": 1, "message": "m", "data": []}},
    {"v": 1, "type": "event", "name": 5},
    {"v": 1, "type": "event", "name": "log", "data": {"level": "TRACE", "message": "x"}},
    {"v": 1, "type": "cancel"},
])
def test_invalid_envelopes(msg):
    with pytest.raises(P.ProtocolError):
        P.validate_message(msg)


def test_unknown_fields_are_ignored_for_forward_compatibility():
    msg = P.request(7, "system.ping", {})
    msg["future_field"] = {"anything": 1}
    assert P.validate_message(msg)["id"] == 7
