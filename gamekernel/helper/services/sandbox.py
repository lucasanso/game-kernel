"""Helper service: behavioural analysis in Windows Sandbox (``sandbox.availability``,
``sandbox.analyze``, ``sandbox.reports``).

Runs in the helper process so the long, blocking orchestration (VM boot, observation, parsing
of data written inside the VM) is isolated from the application. The host must call
``sandbox.analyze`` with a ``timeout_ms`` longer than the observation time plus the VM boot.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...config import Settings
from ...sandbox import manager as SM
from .. import protocol as P
from ..server import RequestContext, Service


def _invalid(message: str, field: str) -> P.ServiceError:
    return P.ServiceError(P.Reason.INVALID_PARAMS, message, {"field": field})


def availability(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    available, reason = SM.check_availability()
    enabled = bool(Settings().get("sandbox.enabled", False))
    return {"available": available, "reason": reason, "enabled_in_settings": enabled,
            "supported_extensions": sorted(SM.SUPPORTED_EXTENSIONS), "limitations": list(SM.LIMITATIONS)}


def analyze(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    unknown = sorted(set(params) - {"path", "timeout_seconds"})
    if unknown:
        raise P.ServiceError(P.Reason.INVALID_PARAMS, f"parâmetros desconhecidos: {unknown}", {"fields": unknown})
    path = params.get("path")
    if not isinstance(path, str) or not path or "\x00" in path or not Path(path).is_absolute():
        raise _invalid("'path' precisa ser um caminho absoluto", "path")
    timeout = params.get("timeout_seconds")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int) or not 30 <= timeout <= 1800):
        raise _invalid("'timeout_seconds' precisa ser um inteiro entre 30 e 1800", "timeout_seconds")
    settings = Settings()
    if not settings.get("sandbox.enabled", False):
        raise P.ServiceError(P.Reason.INVALID_PARAMS,
                             "a análise comportamental está desativada nas configurações", {"field": "settings"})
    manager = SM.SandboxManager(settings)
    try:
        report = manager.analyze(path, timeout, cancel=lambda: ctx.cancelled,
                                 progress=lambda stage, data: ctx.emit("progress", dict(data, stage=stage)))
    except SM.SandboxUnavailable as exc:
        raise P.ServiceError(P.Reason.NOT_FOUND, f"isolamento indisponível; nada foi executado: {exc}",
                             {"executed": False}) from None
    except SM.SandboxError as exc:
        raise P.ServiceError(P.Reason.INVALID_PARAMS, str(exc), {"field": "path"}) from None
    return report.to_dict()


def reports(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
    limit = params.get("limit", 100)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise _invalid("'limit' precisa ser um inteiro entre 1 e 1000", "limit")
    return {"reports": SM.SandboxManager(Settings()).list_reports(limit)}


def services() -> list[Service]:
    return [
        Service("sandbox.availability", availability, "Informa se há isolamento real disponível (nada é executado)."),
        Service("sandbox.analyze", analyze, "Executa a amostra no Windows Sandbox sem rede e retorna evidências."),
        Service("sandbox.reports", reports, "Relatórios de análises comportamentais anteriores."),
    ]
