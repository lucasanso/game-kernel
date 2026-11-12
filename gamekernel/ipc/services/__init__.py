"""Registry of Python services exposed by the helper process (gk-ipc v1).

Each service module exposes ``services() -> list[Service]``. Modules are imported here, at
helper start-up, so an import failure is reported to the host in ``system.info`` instead of
silently removing a feature.
"""

from __future__ import annotations

import importlib
import logging

from ..helper import Service

log = logging.getLogger(__name__)

SERVICE_MODULES: tuple[str, ...] = ()

IMPORT_ERRORS: dict[str, str] = {}


def registry() -> list[Service]:
    out: list[Service] = []
    for name in SERVICE_MODULES:
        try:
            module = importlib.import_module(name)
        except ImportError as exc:
            IMPORT_ERRORS[name] = f"{type(exc).__name__}: {exc}"
            log.error("Serviço indisponível (%s): %s", name, exc)
            continue
        out.extend(module.services())
    return out
