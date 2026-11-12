"""gk-ipc v1 — framed JSON protocol between the Game Kernel application (host) and helper
processes (Python services such as reports and sandbox orchestration).

Transport: the helper's stdin/stdout (anonymous pipes). No sockets are ever used.

Frame: ``uint32 little-endian length`` followed by ``length`` bytes of UTF-8 JSON (an object).
The length must be in ``1..max_frame``. A frame that violates the format makes the stream
unrecoverable: the receiver reports ``protocol_error`` and closes the channel.

Message types (field ``type``), every message carries ``proto`` (major version):

* ``hello``    helper → host, first frame: helper identity, supported methods.
* ``request``  host → helper: ``id``, ``method``, ``params`` (object), optional ``timeout_ms``.
* ``cancel``   host → helper: ``id`` of a pending request.
* ``event``    helper → host: progress/notification for a request (``id``, ``name``, ``data``).
* ``response`` helper → host: ``id``, ``ok`` and either ``result`` or ``error``.
* ``log``      helper → host: ``level``, ``logger``, ``message``.

Versioning: ``proto`` is the major version; peers refuse a different major. Unknown *fields*
are ignored (minor, backwards compatible additions); unknown *types* are protocol errors.
The same rules are implemented by the C++ client in ``native/ipc`` — keep both in sync.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO

PROTOCOL_VERSION = 1
DEFAULT_MAX_FRAME = 8 * 1024 * 1024
HEADER = struct.Struct("<I")
MAX_ID = 2**53 - 1                       # exactly representable in a JSON double (C++/JS safe)
METHOD_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
MESSAGE_TYPES = ("hello", "request", "cancel", "event", "response", "log")


class ErrorCode:
    """Stable error codes shared with the C++ client (native/ipc/include/gk/ipc/protocol.hpp)."""

    PROTOCOL_ERROR = "protocol_error"         # malformed frame/message; channel is closed
    UNSUPPORTED_VERSION = "unsupported_version"
    UNKNOWN_METHOD = "unknown_method"
    INVALID_PARAMS = "invalid_params"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"
    NOT_FOUND = "not_found"
    IO_ERROR = "io_error"
    BUSY = "busy"
    INTERNAL_ERROR = "internal_error"         # unexpected exception inside a service
    HELPER_CRASHED = "helper_crashed"         # host side: the helper process ended
    HELPER_UNAVAILABLE = "helper_unavailable" # host side: helper could not be started

    ALL = (
        PROTOCOL_ERROR, UNSUPPORTED_VERSION, UNKNOWN_METHOD, INVALID_PARAMS, CANCELLED, TIMEOUT,
        RESOURCE_LIMIT, NOT_FOUND, IO_ERROR, BUSY, INTERNAL_ERROR, HELPER_CRASHED, HELPER_UNAVAILABLE,
    )
    RETRYABLE = (TIMEOUT, BUSY, HELPER_CRASHED, HELPER_UNAVAILABLE)


class ProtocolError(Exception):
    """The byte stream or a message violates gk-ipc; the channel must be closed."""


class ChannelClosed(Exception):
    """Clean end of stream (peer closed the pipe between frames)."""


@dataclass
class ServiceError(Exception):
    """Raised by service handlers to return a structured error to the host."""

    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.message)
        if self.code not in ErrorCode.ALL:
            raise ValueError(f"código de erro desconhecido: {self.code}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.code in ErrorCode.RETRYABLE,
            "details": self.details,
        }


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
def _require_id(message: dict[str, Any]) -> int:
    value = message.get("id")
    if isinstance(value, bool) or not isinstance(value, int) or not (1 <= value <= MAX_ID):
        raise ProtocolError("campo 'id' precisa ser um inteiro entre 1 e 2^53-1")
    return value


def validate_message(message: dict[str, Any]) -> dict[str, Any]:
    """Validate the envelope of a decoded message (both directions). Returns the message."""
    proto = message.get("proto")
    if proto != PROTOCOL_VERSION:
        raise ProtocolError(f"versão de protocolo incompatível: {proto!r} (esperado {PROTOCOL_VERSION})")
    kind = message.get("type")
    if kind not in MESSAGE_TYPES:
        raise ProtocolError(f"tipo de mensagem desconhecido: {kind!r}")
    if kind == "request":
        _require_id(message)
        method = message.get("method")
        if not isinstance(method, str) or not METHOD_RE.match(method) or len(method) > 128:
            raise ProtocolError(f"nome de método inválido: {method!r}")
        if not isinstance(message.get("params", {}), dict):
            raise ProtocolError("'params' precisa ser um objeto")
        timeout = message.get("timeout_ms")
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0):
            raise ProtocolError("'timeout_ms' precisa ser um inteiro positivo")
    elif kind == "cancel":
        _require_id(message)
    elif kind == "event":
        _require_id(message)
        if not isinstance(message.get("name"), str) or not isinstance(message.get("data", {}), dict):
            raise ProtocolError("evento precisa de 'name' (texto) e 'data' (objeto)")
    elif kind == "response":
        _require_id(message)
        ok = message.get("ok")
        if ok is True:
            if "result" not in message:
                raise ProtocolError("resposta de sucesso sem 'result'")
        elif ok is False:
            err = message.get("error")
            if not isinstance(err, dict) or not isinstance(err.get("code"), str) or not isinstance(
                err.get("message"), str
            ):
                raise ProtocolError("resposta de erro precisa de 'error.code' e 'error.message'")
        else:
            raise ProtocolError("campo 'ok' precisa ser booleano")
    elif kind == "log":
        if message.get("level") not in LOG_LEVELS or not isinstance(message.get("message"), str):
            raise ProtocolError("log precisa de 'level' válido e 'message'")
    elif kind == "hello":
        if not isinstance(message.get("helper"), str) or not isinstance(message.get("methods"), list):
            raise ProtocolError("hello precisa de 'helper' e 'methods'")
    return message


# ---------------------------------------------------------------------------- builders
def hello(helper: str, version: str, methods: list[str], pid: int, netguard: bool) -> dict[str, Any]:
    return {
        "proto": PROTOCOL_VERSION, "type": "hello", "helper": helper, "version": version,
        "methods": sorted(methods), "pid": pid, "netguard": netguard,
    }


def request(req_id: int, method: str, params: dict[str, Any] | None = None,
            timeout_ms: int | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"proto": PROTOCOL_VERSION, "type": "request", "id": req_id, "method": method,
                           "params": params or {}}
    if timeout_ms is not None:
        msg["timeout_ms"] = int(timeout_ms)
    return msg


def cancel(req_id: int) -> dict[str, Any]:
    return {"proto": PROTOCOL_VERSION, "type": "cancel", "id": req_id}


def event(req_id: int, name: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"proto": PROTOCOL_VERSION, "type": "event", "id": req_id, "name": name, "data": data or {}}


def ok_response(req_id: int, result: Any) -> dict[str, Any]:
    return {"proto": PROTOCOL_VERSION, "type": "response", "id": req_id, "ok": True, "result": result}


def error_response(req_id: int, error: ServiceError) -> dict[str, Any]:
    return {"proto": PROTOCOL_VERSION, "type": "response", "id": req_id, "ok": False, "error": error.to_dict()}


def log(level: str, logger: str, message: str) -> dict[str, Any]:
    return {"proto": PROTOCOL_VERSION, "type": "log", "level": level, "logger": logger, "message": message[:4000]}
