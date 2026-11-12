"""Helper process runtime (Python side of gk-ipc v1).

The C++ application starts ``gk-helper`` (frozen) or ``python -I gk_helper.py`` (development)
with three pipes. The helper answers requests one at a time on a worker thread while the main
thread keeps reading the pipe, so ``cancel`` messages are seen immediately.

Fault isolation guarantees:
* An exception in a service becomes an ``internal_error`` response; the helper keeps running.
* Stray writes to stdout (``print``, C extensions) cannot corrupt the protocol: the protocol
  uses private duplicates of fds 0/1, and fd 1 is redirected to stderr.
* When the host closes the pipe (or dies) the helper cancels pending work and exits.
* Anything worse (segfault in a C extension, out of memory) ends only this process; the host
  reports ``helper_crashed`` and may start a new helper.
"""

from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Callable

from .. import __version__, netguard
from . import protocol as P

log = logging.getLogger(__name__)

HELPER_NAME = "gk-helper"
MAX_QUEUED = 32
SHUTDOWN_GRACE_SECONDS = 5.0


class RequestContext:
    """Passed to every service handler."""

    def __init__(self, server: "HelperServer", req_id: int, method: str, timeout_ms: int | None):
        self._server = server
        self.request_id = req_id
        self.method = method
        self.deadline = time.monotonic() + timeout_ms / 1000.0 if timeout_ms else None
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set() or (self.deadline is not None and time.monotonic() > self.deadline)

    def check(self) -> None:
        """Raise ServiceError(cancelled/timeout) when the request should stop. Call it in loops."""
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise P.ServiceError(P.ErrorCode.TIMEOUT, "tempo limite da operação excedido")
        if self._cancel.is_set():
            raise P.ServiceError(P.ErrorCode.CANCELLED, "operação cancelada pelo aplicativo")

    def emit(self, name: str, data: dict[str, Any] | None = None) -> None:
        self._server.send(P.event(self.request_id, name, data))


Handler = Callable[[dict[str, Any], RequestContext], Any]


@dataclass
class Service:
    method: str
    handler: Handler
    description: str = ""


@dataclass
class _Pending:
    ctx: RequestContext
    params: dict[str, Any]
    started: bool = False
    done: threading.Event = field(default_factory=threading.Event)


class _FrameLogHandler(logging.Handler):
    """Forward log records to the host as ``log`` frames (the host owns the log file)."""

    def __init__(self, server: "HelperServer"):
        super().__init__(logging.INFO)
        self._server = server

    def emit(self, record: logging.LogRecord) -> None:
        try:
            text = record.getMessage()
            if record.exc_info:
                text += "\n" + "".join(traceback.format_exception(*record.exc_info))[-3000:]
            level = record.levelname if record.levelname in P.LOG_LEVELS else "INFO"
            self._server.send(P.log(level, record.name, text))
        except Exception:  # pragma: no cover - never let logging break the helper
            pass


class HelperServer:
    def __init__(self, reader: BinaryIO, writer: BinaryIO, services: list[Service],
                 max_frame: int = P.DEFAULT_MAX_FRAME):
        self._reader = reader
        self._writer = writer
        self._max_frame = max_frame
        self._write_lock = threading.Lock()
        self._services: dict[str, Service] = {}
        self._pending: dict[int, _Pending] = {}
        self._pending_lock = threading.Lock()
        self._queue: queue.Queue[_Pending | None] = queue.Queue()
        self._stopping = threading.Event()
        self._writer_broken = False
        self._exit_code = 0
        for svc in self._builtin_services() + list(services):
            if svc.method in self._services:
                raise ValueError(f"método duplicado: {svc.method}")
            if not P.METHOD_RE.fullmatch(svc.method):
                raise ValueError(f"nome de método inválido: {svc.method}")
            self._services[svc.method] = svc

    # ------------------------------------------------------------------ output
    def send(self, message: dict[str, Any]) -> None:
        frame = P.encode_frame(message, self._max_frame)
        with self._write_lock:
            if self._writer_broken:
                return
            try:
                view = memoryview(frame)
                while view:
                    written = self._writer.write(view)
                    if written is None:  # non-blocking writer would return None; not expected
                        continue
                    view = view[written:]
                self._writer.flush()
            except (BrokenPipeError, OSError, ValueError):
                self._writer_broken = True
                self._stopping.set()

    # ------------------------------------------------------------------ built-in methods
    def _builtin_services(self) -> list[Service]:
        return [
            Service("system.ping", lambda params, ctx: {"pong": True, "echo": params.get("echo")},
                    "Teste de vida do processo auxiliar."),
            Service("system.info", self._info, "Versões, métodos e estado do bloqueio de rede."),
            Service("system.shutdown", self._shutdown, "Encerra o processo auxiliar após responder."),
        ]

    def _info(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        return {
            "helper": HELPER_NAME,
            "version": __version__,
            "protocol": P.PROTOCOL_VERSION,
            "python": sys.version.split()[0],
            "frozen": bool(getattr(sys, "frozen", False)),
            "pid": os.getpid(),
            "netguard": netguard.is_installed(),
            "network_blocked_attempts": len(netguard.blocked_attempts()),
            "methods": {name: svc.description for name, svc in sorted(self._services.items())},
        }

    def _shutdown(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        return {"stopping": True}   # the worker stops the server after this response is written

    # ------------------------------------------------------------------ worker
    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            self._run(item)
            if item.ctx.method == "system.shutdown":
                self._stopping.set()
                return

    def _run(self, item: _Pending) -> None:
        ctx = item.ctx
        try:
            with self._pending_lock:
                item.started = True
            if ctx.cancelled:
                ctx.check()
            svc = self._services[ctx.method]
            result = svc.handler(item.params, ctx)
            try:
                self.send(P.ok_response(ctx.request_id, result))
            except P.ProtocolError as exc:   # result larger than max_frame
                self.send(P.error_response(ctx.request_id, P.ServiceError(P.ErrorCode.RESOURCE_LIMIT, str(exc))))
            except (TypeError, ValueError) as exc:   # result not JSON serialisable
                log.error("Resultado inválido de %s: %s", ctx.method, exc)
                self.send(P.error_response(ctx.request_id, P.ServiceError(
                    P.ErrorCode.INTERNAL_ERROR, f"resultado não serializável: {exc}")))
        except P.ServiceError as exc:
            self.send(P.error_response(ctx.request_id, exc))
        except Exception as exc:  # fault isolation: report, keep serving
            log.error("Falha não tratada em %s", ctx.method, exc_info=True)
            self.send(P.error_response(ctx.request_id, P.ServiceError(
                P.ErrorCode.INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")))
        finally:
            with self._pending_lock:
                self._pending.pop(ctx.request_id, None)
            item.done.set()

    # ------------------------------------------------------------------ input
    def _handle(self, message: dict[str, Any]) -> None:
        kind = message["type"]
        if kind == "request":
            req_id = message["id"]
            method = message["method"]
            if method not in self._services:
                self.send(P.error_response(req_id, P.ServiceError(
                    P.ErrorCode.UNKNOWN_METHOD, f"método desconhecido: {method}")))
                return
            with self._pending_lock:
                if req_id in self._pending:
                    raise P.ProtocolError(f"id de requisição duplicado: {req_id}")
                if len(self._pending) >= MAX_QUEUED:
                    self.send(P.error_response(req_id, P.ServiceError(
                        P.ErrorCode.BUSY, "fila do processo auxiliar cheia")))
                    return
                item = _Pending(RequestContext(self, req_id, method, message.get("timeout_ms")),
                                message.get("params") or {})
                self._pending[req_id] = item
            self._queue.put(item)
        elif kind == "cancel":
            with self._pending_lock:
                item = self._pending.get(message["id"])
            if item is not None:
                item.ctx.cancel()
        else:
            raise P.ProtocolError(f"mensagem '{kind}' não é aceita pelo processo auxiliar")

    def _read_loop(self) -> None:
        try:
            while not self._stopping.is_set():
                try:
                    message = P.validate_message(P.read_frame(self._reader, self._max_frame))
                except P.ChannelClosed:
                    break
                self._handle(message)
        except P.ProtocolError as exc:
            log.error("Erro de protocolo; encerrando o processo auxiliar: %s", exc)
            self._exit_code = 2
        except (OSError, ValueError) as exc:
            log.error("Falha de leitura do canal; encerrando o processo auxiliar: %s", exc)
            self._exit_code = 2
        finally:
            self._stopping.set()

    def serve(self) -> int:
        """Run until the host closes the pipe or requests shutdown. Returns the exit code.

        The pipe is read on a daemon thread so the main thread can stop as soon as
        ``_stopping`` is set (shutdown request, EOF, protocol error or broken output pipe).
        """
        bridge = _FrameLogHandler(self)
        root = logging.getLogger()
        root.addHandler(bridge)
        if root.level > logging.INFO or root.level == logging.NOTSET:
            root.setLevel(logging.INFO)
        worker = threading.Thread(target=self._worker, name="gk-helper-worker", daemon=True)
        reader = threading.Thread(target=self._read_loop, name="gk-helper-reader", daemon=True)
        worker.start()
        try:
            self.send(P.hello(HELPER_NAME, __version__, list(self._services), os.getpid(),
                              netguard.is_installed()))
            reader.start()
            self._stopping.wait()
        finally:
            self._stopping.set()
            with self._pending_lock:
                for item in self._pending.values():
                    item.ctx.cancel()
            self._queue.put(None)
            worker.join(SHUTDOWN_GRACE_SECONDS)
            root.removeHandler(bridge)
        return self._exit_code


# ---------------------------------------------------------------------------- stdio bootstrap
def claim_stdio() -> tuple[BinaryIO, BinaryIO]:
    """Take private duplicates of stdin/stdout for the protocol and neutralise fds 0/1.

    After this call, ``print()`` and native writes to fd 1 land on stderr and nothing can
    consume protocol bytes from fd 0.
    """
    in_fd = os.dup(0)
    out_fd = os.dup(1)
    if sys.platform == "win32":
        import msvcrt

        msvcrt.setmode(in_fd, os.O_BINARY)
        msvcrt.setmode(out_fd, os.O_BINARY)
    null_in = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null_in, 0)
    os.close(null_in)
    try:
        os.dup2(2, 1)
    except OSError:
        null_out = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null_out, 1)
        os.close(null_out)
    sys.stdin = open(os.devnull, encoding="utf-8")  # noqa: SIM115 - lives for the process
    sys.stdout = sys.stderr
    return os.fdopen(in_fd, "rb", buffering=0), os.fdopen(out_fd, "wb", buffering=0)


def default_services() -> list[Service]:
    from .services import registry

    return registry()


def main(argv: list[str] | None = None) -> int:
    reader, writer = claim_stdio()
    server = HelperServer(reader, writer, default_services())
    return server.serve()
