"""Minimal, privacy-preserving description of the computer for forensic reports.

Collected: operating system and build, architecture, CPU model, core counts, total memory,
time-zone offset. **Never** collected: user name, MAC/IP addresses, serial numbers, hardware
IDs, installed software list, domain. The host name is included only when the user enables
``reports.include_hostname``.
"""

from __future__ import annotations

import os
import platform
import sys
import time
from typing import Any

from .. import APP_NAME, __version__


def _windows_cpu_name() -> str | None:
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
            value, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            return str(value).strip() or None
    except OSError:
        return None


def _linux_cpu_name() -> str | None:
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip() or None
    except OSError:
        return None
    return None


def cpu_name() -> str:
    name = _windows_cpu_name() if sys.platform == "win32" else _linux_cpu_name()
    return name or platform.processor() or platform.machine() or "desconhecido"


def os_description() -> dict[str, Any]:
    system = platform.system()
    info: dict[str, Any] = {"system": system, "release": platform.release(), "version": platform.version()}
    if system == "Windows":
        build = 0
        try:
            build = int(platform.version().split(".")[2])
        except (IndexError, ValueError):
            pass
        product = "Windows 11" if build >= 22000 else "Windows 10" if build >= 10240 else f"Windows {platform.release()}"
        edition = platform.win32_edition() if hasattr(platform, "win32_edition") else None
        info.update({"product": product, "build": build or None, "edition": edition or None})
        if product == "Windows 10":
            info["support_note"] = ("O Windows 10 deixou de receber atualizações de segurança gratuitas em "
                                    "14/10/2025; recomenda-se o Windows 11 ou o programa ESU.")
    else:
        info["product"] = f"{system} {platform.release()}".strip()
    return info


def collect(include_hostname: bool = False) -> dict[str, Any]:
    logical = os.cpu_count() or 0
    physical = None
    memory_total = None
    try:
        import psutil

        physical = psutil.cpu_count(logical=False)
        memory_total = int(psutil.virtual_memory().total)
    except Exception:  # psutil optional for this module; report what is known
        pass
    offset = -time.timezone if not time.localtime().tm_isdst else -time.altzone
    data: dict[str, Any] = {
        "os": os_description(),
        "architecture": platform.machine(),
        "cpu": {"model": cpu_name(), "logical_cores": logical, "physical_cores": physical},
        "memory_total_bytes": memory_total,
        "utc_offset_minutes": offset // 60,
        "application": {"name": APP_NAME, "version": __version__},
    }
    if include_hostname:
        data["hostname"] = platform.node()
    return data
