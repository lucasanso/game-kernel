"""Python client for gk-ipc v1 helpers.

Used by automated tests and Python tools. The production host is the C++ client in
``native/ipc`` (QProcess based); both follow docs/INTEGRATION.md.
"""

from __future__ import annotations

import itertools
import logging
import os
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .. import app_paths
from . import protocol as P

log = logging.getLogger(__name__)

HELLO_TIMEOUT = 20.0
ENV_WHITELIST = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOME",
                 "PATH", "LANG", "LC_ALL", "COMSPEC", "PATHEXT", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
                 "QT_QPA_PLATFORM", "GAMEKERNEL_DATA_DIR")


class HelperError(Exception):
    def __init__(self, code: str, message: str, details: dict | None = None, retryable: bool = False):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.details = details or {}
        self.retryable = retryable


@dataclass
class _Call:
    event: threading.Event = field(default_factory=threading.Event)
    response: dict[str, Any] | None = None
    on_event: Callable[[str, dict], None] | None = None


def default_command() -> list[str]:
    """Command that starts the helper of this installation."""
    if app_paths.IS_FROZEN:
        exe = "gk-helper.exe" if app_paths.IS_WINDOWS else "gk-helper"
        return [str(app_paths.install_dir() / exe)]
    script = app_paths.install_dir() / "gk_helper.py"
    return [sys.executable, "-I", str(script)]


def sanitized_environment(data_dir: str | os.PathLike | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k.upper() in ENV_WHITELIST}
    env["GAMEKERNEL_DATA_DIR"] = str(data_dir or app_paths.data_dir())
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


class HelperClient:
    """Synchronous client: one helper process, thread-safe ``call``."""

    def __init__(self, command: list[str] | None = None, env: dict[str, str] | None = None,
                 cwd: str | os.PathLike | None = None, max_frame: int = P.DEFAULT_MAX_FRAME,
                 on_log: Callable[[str, str, str], None] | None = None):
        self.command = command or default_command()
        self.env = env if env is not None else sanitized_environment()
        self.cwd = str(cwd) if cwd else str(Path(self.command[-1]).resolve().parent)
        self.max_frame = max_frame
        self.on_log = on_log
        self.hello: dict[str, Any] | None = None
        self.stderr_tail: deque[str] = deque(maxlen=50)
        self._ids = itertools.count(1)
        self._calls: dict[int, _Call] = {}
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._hello_event = threading.Event()
        self._closed_reason: str | None = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> dict[str, Any]:
        if self._proc is not None and self._proc.poll() is None:
            return self.hello or {}
        flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
        self._hello_event.clear()
        self._closed_reason = None
        self._proc = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.env, cwd=self.cwd, shell=False, creationflags=flags, bufsize=0,
        )
        threading.Thread(target=self._read_loop, args=(self._proc,), daemon=True, name="gk-ipc-reader").start()
        threading.Thread(target=self._stderr_loop, args=(self._proc,), daemon=True, name="gk-ipc-stderr").start()
        if not self._hello_event.wait(HELLO_TIMEOUT) or self.hello is None:
            reason = self._closed_reason or "o processo auxiliar não respondeu ao handshake"
            self.kill()
            raise HelperError(P.ErrorCode.HELPER_UNAVAILABLE, reason, {"stderr": list(self.stderr_tail)})
        return self.hello

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc else None

    def close(self, timeout: float = 5.0) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.poll() is None and proc.stdin:
                proc.stdin.close()   # EOF → helper cancels pending work and exits
            proc.wait(timeout)
        except (OSError, subprocess.TimeoutExpired):
            self.kill()
        finally:
            self._proc = None

    def kill(self) -> None:
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:  # pragma: no cover
                pass

    def __enter__(self) -> "HelperClient":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ I/O threads
    def _read_loop(self, proc: subprocess.Popen) -> None:
        reason = "o processo auxiliar foi encerrado"
        try:
            while True:
                message = P.validate_message(P.read_frame(proc.stdout, self.max_frame))
                self._dispatch(message)
        except P.ChannelClosed:
            pass
        except P.ProtocolError as exc:
            reason = f"erro de protocolo vindo do processo auxiliar: {exc}"
            log.error(reason)
            try:
                proc.kill()
            except OSError:  # pragma: no cover
                pass
        except (OSError, ValueError) as exc:
            reason = f"falha de leitura do processo auxiliar: {exc}"
        try:
            code = proc.wait(5)
            if code not in (0, None):
                reason += f" (código de saída {code})"
        except subprocess.TimeoutExpired:  # pragma: no cover
            pass
        self._closed_reason = reason
        self._hello_event.set()
        with self._lock:
            calls, self._calls = self._calls, {}
        for call in calls.values():
            call.response = {"ok": False, "error": {"code": P.ErrorCode.HELPER_CRASHED, "message": reason,
                                                    "retryable": True, "details": {}}}
            call.event.set()

    def _stderr_loop(self, proc: subprocess.Popen) -> None:
        for raw in iter(proc.stderr.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip()
            if line:
                self.stderr_tail.append(line)

    def _dispatch(self, message: dict[str, Any]) -> None:
        kind = message["type"]
        if kind == "hello":
            self.hello = message
            self._hello_event.set()
        elif kind == "log":
            if self.on_log:
                self.on_log(message["level"], message.get("logger", ""), message["message"])
            else:
                log.log(getattr(logging, message["level"], logging.INFO), "[helper] %s", message["message"])
        elif kind == "event":
            with self._lock:
                call = self._calls.get(message["id"])
            if call and call.on_event:
                call.on_event(message["name"], message.get("data") or {})
        elif kind == "response":
            with self._lock:
                call = self._calls.pop(message["id"], None)
            if call is not None:
                call.response = message
                call.event.set()
        else:
            raise P.ProtocolError(f"o processo auxiliar enviou uma mensagem '{kind}'")

    def _send(self, message: dict[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.poll() is not None or proc.stdin is None:
            raise HelperError(P.ErrorCode.HELPER_CRASHED, self._closed_reason or "processo auxiliar não está ativo",
                              retryable=True)
        frame = P.encode_frame(message, self.max_frame)
        with self._write_lock:
            try:
                proc.stdin.write(frame)
                proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise HelperError(P.ErrorCode.HELPER_CRASHED, f"falha ao enviar: {exc}", retryable=True) from None

    # ------------------------------------------------------------------ calls
    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float = 60.0,
             on_event: Callable[[str, dict], None] | None = None, grace: float = 5.0) -> Any:
        """Call a helper method and return its result, or raise HelperError.

        On timeout a ``cancel`` is sent; if the helper does not answer within ``grace`` seconds
        it is killed (a hung helper must never hang the application).
        """
        if not self.running:
            self.start()
        req_id = next(self._ids)
        call = _Call(on_event=on_event)
        with self._lock:
            self._calls[req_id] = call
        self._send(P.request(req_id, method, params or {}, int(timeout * 1000)))
        timed_out = False
        if not call.event.wait(timeout):
            timed_out = True
            try:
                self._send(P.cancel(req_id))
            except HelperError:
                pass
            if not call.event.wait(grace):
                with self._lock:
                    self._calls.pop(req_id, None)
                self.kill()
                raise HelperError(P.ErrorCode.TIMEOUT, f"'{method}' excedeu {timeout:.0f}s; processo auxiliar encerrado",
                                  retryable=True)
        response = call.response or {}
        if response.get("ok"):
            return response.get("result")
        err = response.get("error") or {}
        if timed_out and err.get("code") in (P.ErrorCode.CANCELLED, P.ErrorCode.TIMEOUT):
            raise HelperError(P.ErrorCode.TIMEOUT, f"'{method}' excedeu {timeout:.0f}s e foi cancelado",
                              retryable=True)
        raise HelperError(err.get("code", P.ErrorCode.INTERNAL_ERROR), err.get("message", "erro desconhecido"),
                          err.get("details"), bool(err.get("retryable")))

    def cancel(self, req_id: int) -> None:
        self._send(P.cancel(req_id))

    def wait_exit(self, timeout: float = 5.0) -> int | None:
        if self._proc is None:
            return None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code = self._proc.poll()
            if code is not None:
                return code
            time.sleep(0.02)
        return None
