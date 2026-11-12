"""Test-only helper with services that misbehave on purpose (exceptions, hard crashes, hangs,
stray stdout writes). Used to prove the fault-isolation guarantees of gk-ipc. Never shipped."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from gamekernel import netguard  # noqa: E402

netguard.install()

from gamekernel.ipc import helper as H  # noqa: E402
from gamekernel.ipc import protocol as P  # noqa: E402


def _sleep(params, ctx):
    end = time.monotonic() + float(params.get("seconds", 1))
    while time.monotonic() < end:
        ctx.check()
        time.sleep(0.01)
    return {"slept": params.get("seconds", 1)}


def _events(params, ctx):
    for i in range(int(params.get("count", 3))):
        ctx.emit("progress", {"i": i})
    return {"sent": int(params.get("count", 3))}


def _stdout(params, ctx):
    print("lixo no stdout que não pode corromper o protocolo")
    os.write(1, b"\x00\x00\x00\x10escrita nativa no fd 1")
    return {"ok": True}


def _raise(params, ctx):
    raise RuntimeError("falha proposital")


def _service_error(params, ctx):
    raise P.ServiceError(P.ErrorCode.INVALID_PARAMS, "parâmetro x inválido", {"field": "x"})


def _crash(params, ctx):
    os._exit(3)


def _hang(params, ctx):
    time.sleep(3600)


def _big(params, ctx):
    return {"blob": "x" * (P.DEFAULT_MAX_FRAME + 10)}


def _not_json(params, ctx):
    return {"value": object()}


def _alloc(params, ctx):
    data = bytearray(int(params.get("mb", 64)) * 1024 * 1024)
    return {"allocated_mb": len(data) // (1024 * 1024)}


def _network(params, ctx):
    import socket

    try:
        socket.create_connection(("192.0.2.1", 443), timeout=0.5)
        return {"blocked": False}
    except netguard.NetworkBlockedError:
        return {"blocked": True}


SERVICES = [H.Service(name, fn) for name, fn in {
    "test.sleep": _sleep, "test.events": _events, "test.stdout": _stdout, "test.raise": _raise,
    "test.service_error": _service_error, "test.crash": _crash, "test.hang": _hang, "test.big": _big,
    "test.not_json": _not_json, "test.network": _network, "test.alloc": _alloc,
}.items()]

if __name__ == "__main__":
    reader, writer = H.claim_stdio()
    sys.exit(H.HelperServer(reader, writer, SERVICES).serve())
