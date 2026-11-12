"""Helper service: forensic report generation (``reports.generate``, ``reports.formats``)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ... import app_paths
from ...config import Settings
from ...core import report_engine as RE
from .. import protocol as P
from ..helper import RequestContext, Service

_ALLOWED_PARAMS = {"scan_id", "formats", "output_dir", "include_clean", "redact_username", "include_hostname",
                   "db_path"}


def _invalid(message: str, **details: Any) -> P.ServiceError:
    return P.ServiceError(P.ErrorCode.INVALID_PARAMS, message, details)


def _bool(params: dict, key: str, default: bool) -> bool:
    value = params.get(key, default)
    if not isinstance(value, bool):
        raise _invalid(f"'{key}' precisa ser booleano", field=key)
    return value


def _abs_path(params: dict, key: str, default: Path) -> Path:
    value = params.get(key)
    if value is None:
        return default
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _invalid(f"'{key}' precisa ser um caminho", field=key)
    path = Path(value)
    if not path.is_absolute():
        raise _invalid(f"'{key}' precisa ser um caminho absoluto", field=key)
    return path


def _formats(params: dict, key: str = "formats") -> list[str]:
    value = params.get(key, ["html", "json"])
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
        raise _invalid("'formats' precisa ser uma lista não vazia", field=key)
    bad = [v for v in value if v not in RE.FORMATS]
    if bad:
        raise _invalid(f"formatos não suportados: {bad}", field=key, supported=list(RE.FORMATS))
    return value


def generate(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    unknown = sorted(set(params) - _ALLOWED_PARAMS)
    if unknown:
        raise _invalid(f"parâmetros desconhecidos: {unknown}", fields=unknown)
    scan_id = params.get("scan_id")
    if isinstance(scan_id, bool) or not isinstance(scan_id, int) or scan_id <= 0:
        raise _invalid("'scan_id' precisa ser um inteiro positivo", field="scan_id")
    settings = Settings()
    options = RE.ReportOptions(
        include_clean=_bool(params, "include_clean", False),
        redact_username=_bool(params, "redact_username", bool(settings.get("reports.redact_username", True))),
        include_hostname=_bool(params, "include_hostname", bool(settings.get("reports.include_hostname", False))),
    )
    output_dir = _abs_path(params, "output_dir", app_paths.reports_dir())
    db_path = _abs_path(params, "db_path", app_paths.db_path())
    formats = _formats(params)
    try:
        return RE.generate(db_path, scan_id, formats, output_dir, options, check=ctx.check,
                           progress=lambda stage, data: ctx.emit("progress", dict(data, stage=stage)))
    except RE.ReportError as exc:
        code = exc.code if exc.code in P.ErrorCode.ALL else P.ErrorCode.INTERNAL_ERROR
        raise P.ServiceError(code, str(exc)) from None
    except PermissionError as exc:
        raise P.ServiceError(P.ErrorCode.IO_ERROR, f"sem permissão: {exc}") from None


def formats(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    available = ["json", "html"]
    detail = {}
    try:
        import reportlab  # noqa: F401

        available.append("pdf")
    except ImportError as exc:
        detail["pdf"] = f"reportlab indisponível: {exc}"
    return {"formats": available, "unavailable": detail, "default_output_dir": str(app_paths.reports_dir()),
            "pid": os.getpid()}


def services() -> list[Service]:
    return [
        Service("reports.generate", generate, "Gera o relatório forense (JSON, HTML, PDF) de uma varredura."),
        Service("reports.formats", formats, "Formatos de relatório disponíveis nesta instalação."),
    ]
