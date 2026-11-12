"""Helper IPC — Python side of the envelope defined in docs/INTEGRATION.md §3 (Agent A's contract).

Transport: the helper's stdin/stdout (anonymous pipes); never sockets.
Frame: ``uint32 little-endian length N`` + N bytes of UTF-8 JSON (an object), 1 ≤ N ≤ 64 MiB.
A frame outside these rules is a protocol error: the channel is closed.

Envelope (``"v": 1`` in every message)::

    hello     child → parent  {"v":1,"type":"hello","component":"gk-helper","version":"1.0.0","protocol":1, …}
    request   parent → child  {"v":1,"id":7,"method":"reports.generate","params":{…}}
    response  child → parent  {"v":1,"id":7,"result":{…}}
                              {"v":1,"id":7,"error":{"code":1003,"message":"…","data":{…}}}
    event     child → parent  {"v":1,"type":"event","name":"progress","data":{…}}
    log       child → parent  {"v":1,"type":"event","name":"log","data":{"level":"INFO","message":"…"}}

Integer error codes (contract): -32600 invalid request · -32601 method not found · -32602 invalid
params · 1001 file inaccessible · 1002 resource limit · 1003 timeout · 1004 cancelled · 1005 invalid format · 1099 internal.

Optional extensions implemented by this helper (documented in contracts/helper_methods.md; readers that
do not know them ignore them, as the contract requires):

* ``request.timeout_ms`` — deadline for cooperative cancellation inside the service;
* ``{"v":1,"type":"cancel","id":7}`` (parent → child) — cancel a pending request;
* ``event.id`` — id of the request the event belongs to;
* ``hello.methods``, ``hello.pid``, ``hello.netguard``;
* ``error.data.reason`` (stable text, more specific than the code: ``invalid_params``, ``not_found``,
  ``busy``…), ``error.data.retryable`` and field-level details such as ``error.data.field``.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO

ENVELOPE_VERSION = 1
PROTOCOL_VERSION = 1
COMPONENT = "gk-helper"
DEFAULT_MAX_FRAME = 64 * 1024 * 1024
HEADER = struct.Struct("<I")
MAX_ID = 2**53 - 1                       # exactly representable in a JSON double (C++/JS safe)
METHOD_RE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")   # always used with fullmatch()
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
TYPED_MESSAGES = ("hello", "event", "cancel")


class ErrorCode:
    """Integer codes of the contract (docs/INTEGRATION.md §3)."""

    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    FILE_INACCESSIBLE = 1001
    RESOURCE_LIMIT = 1002
    TIMEOUT = 1003
    CANCELLED = 1004
    INVALID_FORMAT = 1005
    INTERNAL = 1099


class Reason:
    """Stable reason texts carried in ``error.data.reason`` (extension; finer than the code)."""

    PROTOCOL_ERROR = "protocol_error"
    UNKNOWN_METHOD = "unknown_method"
    INVALID_PARAMS = "invalid_params"
    INVALID_FORMAT = "invalid_format"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"
    BUSY = "busy"
    NOT_FOUND = "not_found"
    IO_ERROR = "io_error"
    INTERNAL_ERROR = "internal_error"
    HELPER_CRASHED = "helper_crashed"         # produced by the parent, never sent by the helper
    HELPER_UNAVAILABLE = "helper_unavailable"  # produced by the parent, never sent by the helper


REASON_TO_CODE = {
    Reason.PROTOCOL_ERROR: ErrorCode.INVALID_REQUEST,
    Reason.INVALID_PARAMS: ErrorCode.INVALID_PARAMS,
    Reason.UNKNOWN_METHOD: ErrorCode.METHOD_NOT_FOUND,
    Reason.NOT_FOUND: ErrorCode.FILE_INACCESSIBLE,
    Reason.IO_ERROR: ErrorCode.FILE_INACCESSIBLE,
    Reason.RESOURCE_LIMIT: ErrorCode.RESOURCE_LIMIT,
    Reason.BUSY: ErrorCode.RESOURCE_LIMIT,
    Reason.TIMEOUT: ErrorCode.TIMEOUT,
    Reason.CANCELLED: ErrorCode.CANCELLED,
    Reason.INVALID_FORMAT: ErrorCode.INVALID_FORMAT,
    Reason.INTERNAL_ERROR: ErrorCode.INTERNAL,
    Reason.HELPER_CRASHED: ErrorCode.INTERNAL,
    Reason.HELPER_UNAVAILABLE: ErrorCode.INTERNAL,
}
RETRYABLE = {Reason.TIMEOUT, Reason.BUSY, Reason.HELPER_CRASHED, Reason.HELPER_UNAVAILABLE}
CODE_TO_REASON = {ErrorCode.INVALID_REQUEST: Reason.PROTOCOL_ERROR, ErrorCode.METHOD_NOT_FOUND: Reason.UNKNOWN_METHOD,
                  ErrorCode.INVALID_PARAMS: Reason.INVALID_PARAMS,
                  ErrorCode.FILE_INACCESSIBLE: Reason.IO_ERROR, ErrorCode.RESOURCE_LIMIT: Reason.RESOURCE_LIMIT,
                  ErrorCode.TIMEOUT: Reason.TIMEOUT, ErrorCode.CANCELLED: Reason.CANCELLED,
                  ErrorCode.INVALID_FORMAT: Reason.INVALID_FORMAT, ErrorCode.INTERNAL: Reason.INTERNAL_ERROR}


class ProtocolError(Exception):
    """The byte stream or a message violates the envelope; the channel must be closed."""


class ChannelClosed(Exception):
    """Clean end of stream (peer closed the pipe between frames)."""


@dataclass
class ServiceError(Exception):
    """Raised by service handlers to return a structured error."""

    reason: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.message)
        if self.reason not in REASON_TO_CODE:
            raise ValueError(f"motivo de erro desconhecido: {self.reason}")

    @property
    def code(self) -> int:
        return REASON_TO_CODE[self.reason]

    def to_error(self) -> dict[str, Any]:
        data = {k: v for k, v in self.details.items() if k not in ("reason", "retryable")}
        data.update(reason=self.reason, retryable=self.reason in RETRYABLE)
        return {"code": self.code, "message": self.message, "data": data}


# ---------------------------------------------------------------------------- framing
def encode_frame(message: dict[str, Any], max_frame: int = DEFAULT_MAX_FRAME) -> bytes:
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if not payload or len(payload) > max_frame:
        raise ProtocolError(f"frame de {len(payload)} bytes excede o limite de {max_frame}")
    return HEADER.pack(len(payload)) + payload


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(stream: BinaryIO, max_frame: int = DEFAULT_MAX_FRAME) -> dict[str, Any]:
    """Read one frame. Raises ChannelClosed on EOF at a frame boundary, ProtocolError otherwise."""
    header = _read_exact(stream, HEADER.size)
    if not header:
        raise ChannelClosed()
    if len(header) != HEADER.size:
        raise ProtocolError("fim de fluxo no meio do cabeçalho do frame")
    (length,) = HEADER.unpack(header)
    if length == 0 or length > max_frame:
        raise ProtocolError(f"tamanho de frame inválido: {length} (limite {max_frame})")
    payload = _read_exact(stream, length)
    if len(payload) != length:
        raise ProtocolError("fim de fluxo no meio do frame")
    return decode_payload(payload)


def decode_payload(payload: bytes) -> dict[str, Any]:
    try:
        message = json.loads(payload.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError(f"JSON inválido: {exc}") from None
    if not isinstance(message, dict):
        raise ProtocolError("a mensagem precisa ser um objeto JSON")
    return message


def _reject_constant(name: str) -> Any:
    raise ValueError(f"constante não permitida: {name}")


# ---------------------------------------------------------------------------- validation
def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_id(message: dict[str, Any]) -> int:
    value = message.get("id")
    if not _is_int(value) or not (1 <= value <= MAX_ID):
        raise ProtocolError("campo 'id' precisa ser um inteiro entre 1 e 2^53-1")
    return value


def kind_of(message: dict[str, Any]) -> str:
    """Classify a validated message: hello | event | cancel | request | response."""
    if "type" in message:
        return message["type"]
    return "request" if "method" in message else "response"


def validate_message(message: dict[str, Any]) -> dict[str, Any]:
    """Validate the envelope of a decoded message (both directions). Returns the message."""
    if message.get("v") != ENVELOPE_VERSION or isinstance(message.get("v"), bool):
        raise ProtocolError(f"versão de envelope incompatível: {message.get('v')!r} (esperado {ENVELOPE_VERSION})")
    if "type" in message:
        kind = message["type"]
        if kind not in TYPED_MESSAGES:
            raise ProtocolError(f"tipo de mensagem desconhecido: {kind!r}")
        if kind == "hello":
            if not isinstance(message.get("component"), str) or not _is_int(message.get("protocol")):
                raise ProtocolError("hello precisa de 'component' (texto) e 'protocol' (inteiro)")
        elif kind == "event":
            if not isinstance(message.get("name"), str) or not isinstance(message.get("data", {}), dict):
                raise ProtocolError("evento precisa de 'name' (texto) e 'data' (objeto)")
            if "id" in message:
                _require_id(message)
            if message["name"] == "log":
                data = message.get("data") or {}
                if data.get("level") not in LOG_LEVELS or not isinstance(data.get("message"), str):
                    raise ProtocolError("evento 'log' precisa de 'level' válido e 'message'")
        else:  # cancel
            _require_id(message)
        return message
    _require_id(message)
    if "method" in message:
        method = message["method"]
        if not isinstance(method, str) or len(method) > 128 or not METHOD_RE.fullmatch(method):
            raise ProtocolError(f"nome de método inválido: {method!r}")
        if not isinstance(message.get("params", {}), dict):
            raise ProtocolError("'params' precisa ser um objeto")
        timeout = message.get("timeout_ms")
        if timeout is not None and (not _is_int(timeout) or timeout <= 0):
            raise ProtocolError("'timeout_ms' precisa ser um inteiro positivo")
        return message
    has_result, has_error = "result" in message, "error" in message
    if has_result == has_error:
        raise ProtocolError("resposta precisa de exatamente um entre 'result' e 'error'")
    if has_error:
        err = message["error"]
        if not isinstance(err, dict) or not _is_int(err.get("code")) or not isinstance(err.get("message"), str):
            raise ProtocolError("erro precisa de 'code' (inteiro) e 'message' (texto)")
        if not isinstance(err.get("data", {}), dict):
            raise ProtocolError("'error.data' precisa ser um objeto")
    return message


# ---------------------------------------------------------------------------- builders
def hello(version: str, methods: list[str], pid: int, netguard: bool) -> dict[str, Any]:
    return {"v": ENVELOPE_VERSION, "type": "hello", "component": COMPONENT, "version": version,
            "protocol": PROTOCOL_VERSION, "methods": sorted(methods), "pid": pid, "netguard": netguard}


def request(req_id: int, method: str, params: dict[str, Any] | None = None,
            timeout_ms: int | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"v": ENVELOPE_VERSION, "id": req_id, "method": method, "params": params or {}}
    if timeout_ms is not None:
        msg["timeout_ms"] = int(timeout_ms)
    return msg


def cancel(req_id: int) -> dict[str, Any]:
    return {"v": ENVELOPE_VERSION, "type": "cancel", "id": req_id}


def event(name: str, data: dict[str, Any] | None = None, req_id: int | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"v": ENVELOPE_VERSION, "type": "event", "name": name, "data": data or {}}
    if req_id is not None:
        msg["id"] = req_id
    return msg


def ok_response(req_id: int, result: Any) -> dict[str, Any]:
    return {"v": ENVELOPE_VERSION, "id": req_id, "result": result}


def error_response(req_id: int, error: ServiceError) -> dict[str, Any]:
    return {"v": ENVELOPE_VERSION, "id": req_id, "error": error.to_error()}


def log(level: str, logger: str, message: str) -> dict[str, Any]:
    return event("log", {"level": level, "logger": logger, "message": message[:4000]})
