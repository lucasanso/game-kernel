"""Local rotating log files. Nothing is ever sent anywhere."""

from __future__ import annotations

import logging
import logging.handlers

from . import app_paths

_CONFIGURED = False


def setup(level: str = "INFO") -> None:
    global _CONFIGURED
    root = logging.getLogger()
    root.setLevel(getattr(logging, level, logging.INFO))
    if _CONFIGURED:
        return
    handler = logging.handlers.RotatingFileHandler(
        app_paths.logs_dir() / "gamekernel.log", maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(processName)s %(name)s: %(message)s"))
    root.addHandler(handler)
    _CONFIGURED = True
