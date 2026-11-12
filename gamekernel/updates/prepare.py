"""Pre-signing checks of update components and the update report.

``check_components`` refuses to package anything the application would reject: YARA rules must
compile (yara-python, same constraints as the C++ installer), IOC files must be valid
``gamekernel-ioc`` without conflicts, ClamAV databases must have sane headers. When the C++
``gk-update`` tool is available, its validators run too (the exact code the app uses), so the
publisher sees the installer's verdict before signing.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from ..intel import ioc
from ..rules import prepare as yara_prep
from . import package as pkg


@dataclass
class PrepResult:
    ok: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    component_meta: dict[str, dict] = field(default_factory=dict)
    native_validation: dict[str, dict] = field(default_factory=dict)

    def fail(self, message: str) -> None:
        self.ok = False
        self.errors.append(message)


def clamav_header_counts(directory: Path) -> tuple[int, list[str]]:
    """Sum the signature counts declared in CVD/CLD/CUD headers; count lines of text databases."""
    total, problems = 0, []
    for path in sorted(p for p in directory.iterdir() if p.is_file()):
        ext = path.suffix.lower()
        if ext in (".cvd", ".cld", ".cud"):
            header = path.open("rb").read(512)
            fields = header.rstrip(b"\x00 \n").split(b":")
            if len(header) != 512 or not header.startswith(b"ClamAV-VDB:") or len(fields) < 8:
                problems.append(f"{path.name}: cabeçalho ClamAV-VDB ausente ou malformado")
                continue
            try:
                total += int(fields[3])
            except ValueError:
                problems.append(f"{path.name}: contagem de assinaturas inválida")
        elif ext in pkg.EXTENSIONS["clamav"]:
            with path.open("rb") as fh:
                total += sum(1 for line in fh if line.strip() and not line.startswith(b"#"))
    return total, problems


def find_gk_update(explicit: str | os.PathLike | None = None) -> Path | None:
    if explicit:
        return Path(explicit) if Path(explicit).is_file() else None
    root = Path(__file__).resolve().parents[2]
    exe = "gk-update.exe" if sys.platform == "win32" else "gk-update"
    for candidate in (root / "build" / "native-updates" / exe, root / "build" / "native-updates" / "Release" / exe):
        if candidate.is_file():
            return candidate
    found = shutil.which("gk-update")
    return Path(found) if found else None


def native_validate(tool: Path, component: str, directory: Path) -> dict:
    proc = subprocess.run([str(tool), "validate", "--component", component, "--dir", str(directory)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, shell=False)
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"ok": False, "messages": [f"saída inesperada do gk-update: {proc.stderr[-500:]}"]}


def check_components(components: dict[str, str | os.PathLike], gk_update: str | os.PathLike | None = None,
                     strict_yara_meta: bool = False) -> PrepResult:
    result = PrepResult()
    for name, directory in components.items():
        directory = Path(directory)
        if name not in pkg.COMPONENTS:
            result.fail(f"componente desconhecido: {name}")
            continue
        if not directory.is_dir():
            result.fail(f"{name}: pasta não encontrada ({directory})")
            continue
        if name == "yara":
            rep = yara_prep.check_rules_dir(directory, strict_meta=strict_yara_meta)
            for e in rep.errors:
                result.fail(f"yara: {e}")
            result.warnings += [f"yara: {w}" for w in rep.warnings]
            result.component_meta["yara"] = {"rule_count": rep.rule_count}
        elif name == "ioc":
            ok, messages, count = ioc.validate_ioc_dir(directory)
            if not ok:
                for m in messages:
                    result.fail(f"ioc: {m}")
            result.component_meta["ioc"] = {"entry_count": count}
        else:
            count, problems = clamav_header_counts(directory)
            for p in problems:
                result.fail(f"clamav: {p}")
            result.component_meta["clamav"] = {"signature_count": count}

    tool = find_gk_update(gk_update)
    if tool is None:
        result.warnings.append("gk-update (validadores C++) não encontrado: só as verificações Python foram feitas")
    elif result.ok:
        for name, directory in components.items():
            verdict = native_validate(tool, name, Path(directory))
            result.native_validation[name] = verdict
            if not verdict.get("ok"):
                for m in verdict.get("messages") or ["reprovado"]:
                    result.fail(f"{name} (validador C++): {m}")
    return result


def update_report(manifest: dict, prep: PrepResult, previous: str | os.PathLike | None = None,
                  keys: dict | None = None) -> dict:
    """Human/auditable report of a package: components, counts, files, diff to the previous package."""
    files = {f["path"]: f for f in manifest["files"]}
    report = {
        "format": "gamekernel-update-report",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "package_id": manifest["package_id"],
        "package_version": manifest["package_version"],
        "publisher": manifest["publisher"],
        "signing_key_id": manifest["signing_key_id"],
        "min_app_version": manifest["min_app_version"],
        "components": {name: dict(meta, **prep.component_meta.get(name, {}))
                       for name, meta in manifest["components"].items()},
        "files": [{"path": f["path"], "size": f["size"], "sha256": f["sha256"]} for f in manifest["files"]],
        "total_bytes": sum(f["size"] for f in manifest["files"]),
        "warnings": prep.warnings,
        "native_validation": prep.native_validation,
    }
    if previous:
        try:
            old = pkg.verify_package(previous, keys or {}).manifest
        except pkg.PackageError as exc:
            report["diff"] = {"error": f"pacote anterior não verificado: {exc}"}
        else:
            old_files = {f["path"]: f for f in old["files"]}
            report["diff"] = {
                "previous_version": old["package_version"],
                "added": sorted(set(files) - set(old_files)),
                "removed": sorted(set(old_files) - set(files)),
                "changed": sorted(p for p in set(files) & set(old_files)
                                  if files[p]["sha256"] != old_files[p]["sha256"]),
            }
    return report
