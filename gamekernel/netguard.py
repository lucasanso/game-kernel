"""Process-wide network guard.

Game Kernel never needs the network. This module installs a Python audit hook
(PEP 578) that rejects every outbound network primitive exposed to Python code:
socket connections, DNS resolution, datagram sends, urllib/http/ftp/smtp
clients and ``webbrowser``.  Audit hooks cannot be removed once installed, so
third-party libraries loaded later are covered as well.

Loopback traffic is denied too, except for the private socket pairs the
standard library creates internally (``socket.socketpair`` on Windows uses a
127.0.0.1 TCP pair).  Every blocked attempt is recorded and shown in the
"Privacidade e rede" page.

Limitations (documented in docs/PRIVACY.md): native code that opens sockets
without going through Python (e.g. a C library) is not seen by audit hooks.
Game Kernel does not bundle such components; the installer additionally offers
Windows Firewall outbound block rules for the executables it ships.
"""

from __future__ import annotations

import ipaddress
import os
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field

_BLOCKED_EVENTS_ALWAYS = {
    "urllib.Request",
    "http.client.connect",
    "http.client.send",
    "ftplib.connect",
    "smtplib.connect",
    "poplib.connect",
    "imaplib.open",
    "nntplib.connect",
    "telnetlib.Telnet.open",
    "webbrowser.open",
    "socket.gethostbyname",
    "socket.gethostbyname_ex",
    "socket.gethostbyaddr",
    "socket.getnameinfo",
}

_ADDRESS_EVENTS = {"socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind"}


class NetworkBlockedError(PermissionError):
    """Raised when code inside Game Kernel tries to use the network."""


@dataclass
class BlockedAttempt:
    timestamp: float
    event: str
    target: str
    origin: str


@dataclass
class _GuardState:
    installed: bool = False
    blocked: list[BlockedAttempt] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


_STATE = _GuardState()
_MAX_RECORDS = 500


def _is_loopback(host: object) -> bool:
    if host in (None, "", "localhost"):
        return True
    try:
        return ipaddress.ip_address(str(host).split("%")[0]).is_loopback
    except ValueError:
        return False


def _describe(args: tuple) -> str:
    try:
        return repr(args[1] if len(args) > 1 else args)[:200]
    except Exception:  # pragma: no cover - defensive
        return "<unprintable>"


def _origin() -> str:
    frames = traceback.extract_stack(limit=12)[:-3]
    for frame in reversed(frames):
        if "netguard" not in frame.filename:
            return f"{os.path.basename(frame.filename)}:{frame.lineno} ({frame.name})"
    return "?"


def _record(event: str, target: str) -> None:
    with _STATE.lock:
        if len(_STATE.blocked) >= _MAX_RECORDS:
            _STATE.blocked.pop(0)
        _STATE.blocked.append(BlockedAttempt(time.time(), event, target, _origin()))


def _hook(event: str, args: tuple) -> None:
    if event in _BLOCKED_EVENTS_ALWAYS:
        target = _describe(args)
        _record(event, target)
        raise NetworkBlockedError(f"Game Kernel opera offline: '{event}' bloqueado ({target})")

    if event == "socket.getaddrinfo":
        host = args[0] if args else None
        if _is_loopback(host if not isinstance(host, bytes) else host.decode(errors="ignore")):
            return
        _record(event, repr(host)[:200])
        raise NetworkBlockedError(f"Game Kernel opera offline: resolução DNS bloqueada ({host!r})")

    if event in _ADDRESS_EVENTS:
        address = args[1] if len(args) > 1 else None
        if isinstance(address, (str, bytes)):  # AF_UNIX path / abstract socket
            return
        if isinstance(address, tuple) and address and _is_loopback(address[0]):
            # Loopback only: used internally by socket.socketpair() on Windows.
            return
        if address is None:
            return
        _record(event, _describe(args))
        raise NetworkBlockedError(f"Game Kernel opera offline: '{event}' para {address!r} bloqueado")


def install() -> None:
    """Install the guard (idempotent). Must run before any other import that may use sockets."""
    if _STATE.installed:
        return
    sys.addaudithook(_hook)
    _STATE.installed = True
    # Make sure proxy auto-detection in any library can never point somewhere.
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(var, None)
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"


def is_installed() -> bool:
    return _STATE.installed


def blocked_attempts() -> list[BlockedAttempt]:
    with _STATE.lock:
        return list(_STATE.blocked)


def self_test() -> dict:
    """Actively verify the guard: try to resolve and connect, expect both to be blocked."""
    import socket

    results = {}
    try:
        socket.getaddrinfo("example.com", 443)
        results["dns"] = "PERMITIDO (falha)"
    except NetworkBlockedError:
        results["dns"] = "bloqueado"
    except OSError as exc:  # guard not installed and no network available
        results["dns"] = f"erro de rede: {exc}"
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect(("192.0.2.1", 443))  # TEST-NET-1, never routable
        results["connect"] = "PERMITIDO (falha)"
    except NetworkBlockedError:
        results["connect"] = "bloqueado"
    except OSError as exc:
        results["connect"] = f"erro de rede: {exc}"
    finally:
        if sock is not None:
            sock.close()
    results["ok"] = results["dns"] == "bloqueado" and results["connect"] == "bloqueado"
    return results
